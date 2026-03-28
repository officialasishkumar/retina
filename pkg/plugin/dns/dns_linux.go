// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package dns contains the Retina DNS plugin. It uses eBPF socket filters to capture DNS events.
package dns

import (
	"context"
	"net"
	"syscall"
	"unsafe"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/microsoft/retina/internal/ktime"
	kcfg "github.com/microsoft/retina/pkg/config"
	"github.com/microsoft/retina/pkg/enricher"
	"github.com/microsoft/retina/pkg/log"
	"github.com/microsoft/retina/pkg/metrics"
	plugincommon "github.com/microsoft/retina/pkg/plugin/common"
	"github.com/microsoft/retina/pkg/plugin/registry"
	"github.com/microsoft/retina/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Per-arch target needed because vmlinux.h differs between amd64/arm64.
// Cross-generate: GOARCH=arm64 go generate ./pkg/plugin/dns/...
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -cflags "-Wall" -target ${GOARCH} -type dns_event dns ./_cprog/dns.c -- -I../lib/_${GOARCH} -I../lib/common/libbpf/_src

const (
	soAttachBPF   = 50   // SO_ATTACH_BPF
	perCPUBuffer  = 8192 // Per-CPU buffer pages for perf reader
	recordsBuffer = 1000 // Channel buffer for records
	workers       = 2    // Number of worker goroutines
)

func init() {
	registry.Add(name, New)
}

func New(cfg *kcfg.Config) registry.Plugin {
	return &dns{
		cfg: cfg,
		l:   log.Logger().Named(name),
	}
}

func (d *dns) Name() string {
	return name
}

// Generate and Compile are no-ops. The plugin manager lifecycle requires them,
// but DNS uses bpf2go which pre-compiles the BPF program at build time and
// embeds it in the binary — no runtime code generation or compilation needed.
func (d *dns) Generate(_ context.Context) error { return nil }
func (d *dns) Compile(_ context.Context) error  { return nil }

func (d *dns) Init() error {
	objs := &dnsObjects{}
	if err := loadDnsObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: plugincommon.MapPath,
		},
	}); err != nil {
		return errors.Wrap(err, "failed to load eBPF objects")
	}
	d.objs = objs

	// Bind to the default route interface to avoid AF_PACKET double-counting.
	ifIndex, ifErr := utils.GetDefaultIfaceIndex()
	if ifErr != nil {
		d.l.Warn("Could not determine default interface, falling back to all interfaces", zap.Error(ifErr))
	}
	sock, err := utils.OpenRawSocket(ifIndex)
	if err != nil {
		return errors.Wrap(err, "failed to open raw socket")
	}
	d.sock = sock

	if attachErr := syscall.SetsockoptInt(d.sock, syscall.SOL_SOCKET, soAttachBPF, objs.RetinaDnsFilter.FD()); attachErr != nil {
		return errors.Wrap(attachErr, "failed to attach BPF to socket")
	}

	reader, err := plugincommon.NewPerfReader(d.l, objs.RetinaDnsEvents, perCPUBuffer, 1)
	if err != nil {
		return errors.Wrap(err, "failed to create perf reader")
	}
	d.reader = reader

	d.l.Info("DNS plugin initialized")
	return nil
}

func (d *dns) Start(ctx context.Context) error {
	d.isRunning = true
	d.recordsChannel = make(chan perf.Record, recordsBuffer)

	if d.cfg.EnablePodLevel {
		if enricher.IsInitialized() {
			d.enricher = enricher.Instance()
		} else {
			d.l.Warn("retina enricher is not initialized")
		}
	}

	return d.run(ctx)
}

func (d *dns) run(ctx context.Context) error {
	for i := range workers {
		d.wg.Add(1)
		go d.processRecord(ctx, i)
	}
	go d.readEvents(ctx)

	<-ctx.Done()
	d.wg.Wait()
	return nil
}

func (d *dns) readEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := d.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				d.l.Error("Error reading perf event", zap.Error(err))
				continue
			}

			if record.LostSamples > 0 {
				metrics.LostEventsCounter.WithLabelValues(utils.Kernel, name).Add(float64(record.LostSamples))
				continue
			}

			select {
			case d.recordsChannel <- record:
			default:
				metrics.LostEventsCounter.WithLabelValues(utils.BufferedChannel, name).Inc()
			}
		}
	}
}

func (d *dns) processRecord(ctx context.Context, _ int) {
	defer d.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case record := <-d.recordsChannel:
			d.handleDNSEvent(record)
		}
	}
}

func (d *dns) handleDNSEvent(record perf.Record) {
	eventSize := int(unsafe.Sizeof(dnsDnsEvent{}))
	if len(record.RawSample) < eventSize {
		return
	}

	event := (*dnsDnsEvent)(unsafe.Pointer(&record.RawSample[0])) //nolint:gosec // perf record is aligned

	// Increment basic counter (always, regardless of pod-level)
	if event.Qr == 0 {
		metrics.DNSRequestCounter.WithLabelValues().Inc()
	} else {
		metrics.DNSResponseCounter.WithLabelValues().Inc()
	}

	if !d.cfg.EnablePodLevel {
		return
	}

	// Direction from packet type
	var dir uint8
	switch event.PktType {
	case 0: // PACKET_HOST (incoming)
		dir = 2 // Ingress
	case 4: // PACKET_OUTGOING
		dir = 3 // Egress
	default:
		return
	}

	// IP addresses — copy raw bytes, no endian conversion needed
	var srcIP, dstIP net.IP
	switch event.Af {
	case 4:
		var srcBuf, dstBuf [net.IPv4len]byte
		*(*uint32)(unsafe.Pointer(&srcBuf[0])) = event.SrcIp //nolint:gosec // same size
		*(*uint32)(unsafe.Pointer(&dstBuf[0])) = event.DstIp //nolint:gosec // same size
		srcIP = srcBuf[:]
		dstIP = dstBuf[:]
	case 6:
		srcIP = event.SrcIp6[:]
		dstIP = event.DstIp6[:]
	default:
		return
	}

	// Parse DNS name and response addresses from the packet payload.
	// Query type comes from BPF (event.Qtype), not gopacket.
	var dnsName string
	var addresses []string
	if packetData := record.RawSample[eventSize:]; len(packetData) > 0 && int(event.DnsOff) < len(packetData) {
		dnsName, addresses = d.parseDNSPayload(packetData[event.DnsOff:], event.Qr == 1)
	}
	qTypes := []string{layers.DNSType(event.Qtype).String()}

	var qrStr string
	if event.Qr == 0 {
		qrStr = "Q"
	} else {
		qrStr = "R"
	}

	fl := utils.ToFlow(
		d.l,
		ktime.MonotonicOffset.Nanoseconds()+int64(event.Timestamp), //nolint:gosec // timestamp fits in int64
		srcIP, dstIP,
		uint32(event.SrcPort), uint32(event.DstPort),
		event.Proto, dir,
		utils.Verdict_DNS,
	)
	if fl == nil {
		return
	}

	ext := utils.NewExtensions()
	utils.AddDNSInfo(fl, ext, qrStr, uint32(event.Rcode), dnsName, qTypes, int(event.Ancount), addresses)
	utils.SetExtensions(fl, ext)

	ev := &v1.Event{
		Event:     fl,
		Timestamp: fl.GetTime(),
	}

	if d.enricher != nil {
		d.enricher.Write(ev)
	}

	if d.externalChannel != nil {
		select {
		case d.externalChannel <- ev:
		default:
			metrics.LostEventsCounter.WithLabelValues(utils.ExternalChannel, name).Inc()
		}
	}
}

// parseDNSPayload extracts the query name and response addresses from the DNS
// payload. Query type is extracted by BPF, not here.
func (d *dns) parseDNSPayload(payload []byte, isResponse bool) (dnsName string, addresses []string) {
	if len(payload) < 12 {
		return "", nil
	}

	// gopacket's DNS decoder can panic on malformed input.
	defer func() {
		if r := recover(); r != nil {
			d.l.Debug("DNS decode panic (malformed packet)", zap.Any("recover", r))
			dnsName, addresses = "", nil
		}
	}()

	var parser layers.DNS
	if err := parser.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return "", nil
	}

	if len(parser.Questions) > 0 {
		dnsName = string(parser.Questions[0].Name) + "."
	}

	if isResponse {
		for i := range parser.Answers {
			if parser.Answers[i].IP != nil {
				addresses = append(addresses, parser.Answers[i].IP.String())
			}
		}
	}

	return dnsName, addresses
}

func (d *dns) Stop() error {
	if !d.isRunning {
		return nil
	}
	if d.reader != nil {
		d.reader.Close()
	}
	if d.sock != 0 {
		syscall.Close(d.sock) //nolint:errcheck // best-effort cleanup
	}
	if d.objs != nil {
		d.objs.Close()
	}
	d.isRunning = false
	return nil
}

func (d *dns) SetupChannel(c chan *v1.Event) error {
	d.externalChannel = c
	return nil
}
