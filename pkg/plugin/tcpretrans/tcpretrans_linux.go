// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package tcpretrans contains the Retina tcpretrans plugin. It utilizes eBPF to trace TCP retransmissions.
package tcpretrans

import (
	"context"
	"net"
	"unsafe"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
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
	"golang.org/x/sys/unix"
)

// Per-arch target needed because vmlinux.h differs between amd64/arm64.
// Cross-generate: GOARCH=arm64 go generate ./pkg/plugin/tcpretrans/...
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -cflags "-Wall" -target ${GOARCH} -type tcpretrans_event tcpretrans ./_cprog/tcpretrans.c -- -I../lib/_${GOARCH} -I../lib/common/libbpf/_src

const (
	perCPUBuffer  = 4096 // Per-CPU buffer pages for perf reader
	recordsBuffer = 500  // Channel buffer for records
	workers       = 2    // Number of worker goroutines
)

func init() {
	registry.Add(name, New)
}

func New(cfg *kcfg.Config) registry.Plugin {
	return &tcpretrans{
		cfg: cfg,
		l:   log.Logger().Named(name),
	}
}

func (t *tcpretrans) Name() string {
	return name
}

// Generate and Compile are no-ops. The plugin manager lifecycle requires them,
// but tcpretrans uses bpf2go which pre-compiles the BPF program at build time
// and embeds it in the binary — no runtime code generation or compilation needed.
func (t *tcpretrans) Generate(_ context.Context) error { return nil }
func (t *tcpretrans) Compile(_ context.Context) error  { return nil }

func (t *tcpretrans) Init() error {
	if !t.cfg.EnablePodLevel {
		t.l.Warn("tcpretrans will not init because pod level is disabled")
		return nil
	}

	objs := &tcpretransObjects{}
	if err := loadTcpretransObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: plugincommon.MapPath,
		},
	}); err != nil {
		return errors.Wrap(err, "failed to load eBPF objects")
	}
	t.objs = objs

	// Attach to the tcp/tcp_retransmit_skb tracepoint (stable API, kernel 4.16+)
	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", objs.RetinaTcpRetransmitSkb, nil)
	if err != nil {
		return errors.Wrap(err, "failed to attach tracepoint tcp/tcp_retransmit_skb")
	}
	t.hooks = append(t.hooks, tp)

	reader, err := plugincommon.NewPerfReader(t.l, objs.RetinaTcpretransEvents, perCPUBuffer, 1)
	if err != nil {
		return errors.Wrap(err, "failed to create perf reader")
	}
	t.reader = reader

	t.l.Info("tcpretrans plugin initialized")
	return nil
}

func (t *tcpretrans) Start(ctx context.Context) error {
	if !t.cfg.EnablePodLevel {
		t.l.Warn("tcpretrans will not start because pod level is disabled")
		return nil
	}

	t.isRunning = true

	if enricher.IsInitialized() {
		t.enricher = enricher.Instance()
	} else {
		t.l.Warn("retina enricher is not initialized")
	}

	t.recordsChannel = make(chan perf.Record, recordsBuffer)

	return t.run(ctx)
}

func (t *tcpretrans) run(ctx context.Context) error {
	for i := range workers {
		t.wg.Add(1)
		go t.processRecord(ctx, i)
	}
	go t.readEvents(ctx)

	<-ctx.Done()
	t.wg.Wait()
	return nil
}

func (t *tcpretrans) readEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := t.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				t.l.Error("Error reading perf event", zap.Error(err))
				continue
			}

			if record.LostSamples > 0 {
				metrics.LostEventsCounter.WithLabelValues(utils.Kernel, name).Add(float64(record.LostSamples))
				continue
			}

			select {
			case t.recordsChannel <- record:
			default:
				metrics.LostEventsCounter.WithLabelValues(utils.BufferedChannel, name).Inc()
			}
		}
	}
}

func (t *tcpretrans) processRecord(ctx context.Context, _ int) {
	defer t.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case record := <-t.recordsChannel:
			t.handleTCPRetransEvent(record)
		}
	}
}

func (t *tcpretrans) handleTCPRetransEvent(record perf.Record) {
	eventSize := int(unsafe.Sizeof(tcpretransTcpretransEvent{}))
	if len(record.RawSample) < eventSize {
		return
	}

	event := (*tcpretransTcpretransEvent)(unsafe.Pointer(&record.RawSample[0])) //nolint:gosec // perf record is aligned

	var srcIP, dstIP net.IP
	switch event.Af {
	case 4: // IPv4
		var srcBuf, dstBuf [net.IPv4len]byte
		*(*uint32)(unsafe.Pointer(&srcBuf[0])) = event.SrcIp //nolint:gosec // same size
		*(*uint32)(unsafe.Pointer(&dstBuf[0])) = event.DstIp //nolint:gosec // same size
		srcIP = srcBuf[:]
		dstIP = dstBuf[:]
	case 6: // IPv6
		srcIP = event.SrcIp6[:]
		dstIP = event.DstIp6[:]
	default:
		return
	}

	fl := utils.ToFlow(
		t.l,
		ktime.MonotonicOffset.Nanoseconds()+int64(event.Timestamp), //nolint:gosec // timestamp fits in int64
		srcIP, dstIP,
		uint32(event.SrcPort), uint32(event.DstPort),
		unix.IPPROTO_TCP, 0,
		utils.Verdict_RETRANSMISSION,
	)
	if fl == nil {
		return
	}

	syn := flagBit(event.Tcpflags, 0x02)
	ack := flagBit(event.Tcpflags, 0x10)
	fin := flagBit(event.Tcpflags, 0x01)
	rst := flagBit(event.Tcpflags, 0x04)
	psh := flagBit(event.Tcpflags, 0x08)
	urg := flagBit(event.Tcpflags, 0x20)
	ece := flagBit(event.Tcpflags, 0x40)
	cwr := flagBit(event.Tcpflags, 0x80)
	utils.AddTCPFlags(fl, syn, ack, fin, rst, psh, urg, ece, cwr, 0)

	ev := &v1.Event{
		Event:     fl,
		Timestamp: fl.Time,
	}

	if t.enricher != nil {
		t.enricher.Write(ev)
	}

	if t.externalChannel != nil {
		select {
		case t.externalChannel <- ev:
		default:
			metrics.LostEventsCounter.WithLabelValues(utils.ExternalChannel, name).Inc()
		}
	}
}

func (t *tcpretrans) Stop() error {
	if !t.cfg.EnablePodLevel || !t.isRunning {
		return nil
	}
	if t.reader != nil {
		t.reader.Close()
	}
	for _, h := range t.hooks {
		h.Close()
	}
	if t.objs != nil {
		t.objs.Close()
	}
	t.isRunning = false
	return nil
}

func (t *tcpretrans) SetupChannel(ch chan *v1.Event) error {
	t.externalChannel = ch
	return nil
}

func flagBit(flags, bit uint8) uint16 {
	if flags&bit != 0 {
		return 1
	}
	return 0
}
