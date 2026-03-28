// go:build ignore

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// TCP retransmission tracer — tracepoint on tcp/tcp_retransmit_skb.
// Captures the 5-tuple, TCP state, and flags from retransmitted packets.
//
// Ref: https://github.com/inspektor-gadget/inspektor-gadget/blob/c414fc1/gadgets/trace_tcpretrans/program.bpf.c

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Sent to userspace via perf buffer.
// Fields ordered by descending alignment to minimize padding.
struct tcpretrans_event {
	__u64 timestamp;  // Boot time in nanoseconds
	__u32 src_ip;	  // Source IPv4 (network byte order)
	__u32 dst_ip;	  // Destination IPv4 (network byte order)
	__u32 state;	  // TCP state (e.g., ESTABLISHED, SYN_SENT)
	__u16 src_port;	  // Source port (host byte order)
	__u16 dst_port;	  // Destination port (host byte order)
	__u8 src_ip6[16]; // Source IPv6 address
	__u8 dst_ip6[16]; // Destination IPv6 address
	__u8 tcpflags;	  // TCP flags byte (SYN/ACK/FIN/RST/etc.)
	__u8 af;	  // Address family (4=IPv4, 6=IPv6)
};

// Required by bpf2go -type flag (perf payload, not a map key/value).
const struct tcpretrans_event *unused_tcpretrans_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} retina_tcpretrans_events SEC(".maps");

// Tracepoint fields must be read via BPF_CORE_READ — direct ctx->field
// access is not allowed by the verifier for tracepoint programs.
SEC("tracepoint/tcp/tcp_retransmit_skb")
int retina_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx) {
	struct tcpretrans_event event = {};

	event.timestamp = bpf_ktime_get_boot_ns();
	event.state = BPF_CORE_READ(ctx, state);
	event.src_port = BPF_CORE_READ(ctx, sport);
	event.dst_port = BPF_CORE_READ(ctx, dport);

	// Address family from the sock (the tracepoint struct doesn't always
	// include it depending on kernel version).
	const struct sock *sk = (const struct sock *)BPF_CORE_READ(ctx, skaddr);
	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	if (family == 2) { // AF_INET
		event.af = 4;
		BPF_CORE_READ_INTO(&event.src_ip, ctx, saddr);
		BPF_CORE_READ_INTO(&event.dst_ip, ctx, daddr);
	} else if (family == 10) { // AF_INET6
		event.af = 6;
		BPF_CORE_READ_INTO(event.src_ip6, ctx, saddr_v6);
		BPF_CORE_READ_INTO(event.dst_ip6, ctx, daddr_v6);
	} else {
		return 0;
	}

	// TCP flags live in tcp_skb_cb (the control buffer at skb->cb), not in
	// the transport header — the retransmit skb is built from a clone that
	// doesn't carry the TCP header.
	// Ref: https://github.com/inspektor-gadget/inspektor-gadget/blob/c414fc1/gadgets/trace_tcpretrans/program.bpf.c#L124-L131
	const void *skbaddr = (const void *)BPF_CORE_READ(ctx, skbaddr);
	if (skbaddr) {
		bpf_probe_read_kernel(
			&event.tcpflags, sizeof(event.tcpflags),
			skbaddr + offsetof(struct sk_buff, cb) +
				offsetof(struct tcp_skb_cb, tcp_flags));
	}

	bpf_perf_event_output(ctx, &retina_tcpretrans_events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}
