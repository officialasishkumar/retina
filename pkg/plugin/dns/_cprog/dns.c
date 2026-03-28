// go:build ignore

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// DNS tracer eBPF program - captures DNS queries and responses
//
// Adapted from Inspektor Gadget's trace_dns gadget (Apache 2.0 License)
// https://github.com/inspektor-gadget/inspektor-gadget
// Copyright (c) The Inspektor Gadget authors

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Ethernet and IP constants
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_HLEN 14

// IP protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// IPv6 next header values
#define NEXTHDR_HOP 0
#define NEXTHDR_TCP 6
#define NEXTHDR_UDP 17
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH 51
#define NEXTHDR_NONE 59
#define NEXTHDR_DEST 60

// Packet types from linux/if_packet.h
#define PACKET_HOST 0	  // Incoming packets
#define PACKET_OUTGOING 4 // Outgoing packets

// DNS constants
#define DNS_PORT 53
#define DNS_MDNS_PORT 5353
#define DNS_QR_QUERY 0
#define DNS_QR_RESP 1

// Maximum ports to check
#define MAX_PORTS 16
const volatile __u16 dns_ports[MAX_PORTS] = {DNS_PORT, DNS_MDNS_PORT};
const volatile __u16 dns_ports_len = 2;

// BPF packet access intrinsics for socket filter programs.
// Unlike direct memory access, these handle the sk_buff indirection and
// convert from network byte order (big-endian) to host byte order:
//   load_byte: reads 1 byte  (no conversion needed)
//   load_half: reads 2 bytes (applies ntohs)
unsigned long long load_byte(const void *skb,
							 unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(const void *skb,
							 unsigned long long off) asm("llvm.bpf.load.half");

// DNS header structure (RFC 1035 §4.1.1).
// We only use this for sizeof and offsetof — flag fields (QR, RCODE)
// are extracted manually via load_byte to avoid bitfield portability issues.
struct dnshdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount; // Question count
	__u16 ancount; // Answer count
	__u16 nscount; // Authority records
	__u16 arcount; // Additional records
};

// DNS event structure - sent to userspace.
// Fields are ordered by descending alignment (8 → 4 → 2 → 1) to avoid
// internal padding. The compiler adds 5 bytes of trailing padding to
// reach 8-byte struct alignment (required by the __u64 field).
struct dns_event {
	__u64 timestamp;  // Boot time in nanoseconds
	__u32 src_ip;	  // Source IPv4 address
	__u32 dst_ip;	  // Destination IPv4 address
	__u8 src_ip6[16]; // Source IPv6 address
	__u8 dst_ip6[16]; // Destination IPv6 address
	__u16 src_port;	  // Source port
	__u16 dst_port;	  // Destination port
	__u16 id;		  // DNS query ID
	__u16 qtype;	  // Query type (from first question)
	__u16 ancount;	  // Answer count
	__u16 dns_off;	  // DNS offset in packet
	__u16 data_len;	  // Total packet length
	__u8 af;		  // Address family (4 or 6)
	__u8 proto;		  // Protocol (TCP=6, UDP=17)
	__u8 pkt_type;	  // Packet type (HOST=0, OUTGOING=4)
	__u8 qr;		  // Query(0) or Response(1)
	__u8 rcode;		  // Response code
};

// Force bpf2go to generate a Go type for dns_event. Without this,
// bpf2go only generates types that appear in map definitions or
// program parameters. The -type flag references this symbol.
const struct dns_event *unused_dns_event __attribute__((unused));

// Perf event array for streaming events to userspace
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} retina_dns_events SEC(".maps");

// BPF programs only get 512 bytes of stack, which is too small to hold
// a dns_event struct plus local variables. Instead we use a per-CPU array
// map with a single entry as heap-like scratch space — each CPU gets its
// own copy so there are no data races.
// Ref:
// https://github.com/inspektor-gadget/inspektor-gadget/blob/c414fc1/gadgets/trace_dns/program.bpf.c#L103-L109
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_event);
} tmp_dns_events SEC(".maps");

// Check if port is a DNS port
static __always_inline bool is_dns_port(__u16 port) {
#pragma unroll
	for (int i = 0; i < MAX_PORTS; i++) {
		if (i >= dns_ports_len)
			break;
		if (dns_ports[i] == port)
			return true;
	}
	return false;
}

// Socket filter attached to a raw AF_PACKET socket. Runs on every packet
// received by that socket. Filters for DNS traffic (port 53/5353), extracts
// header metadata into a dns_event struct, and sends it to userspace via
// perf buffer with the raw packet appended for Go-side DNS payload parsing.
SEC("socket1")
int retina_dns_filter(struct __sk_buff *skb) {
	struct dns_event *event;
	__u16 h_proto, sport, dport, l4_off, dns_off;
	__u8 proto;
	int zero = 0;

	// Only process packets destined for or originating from this host.
	// Skip forwarded/broadcast/multicast traffic to match per-pod semantics.
	if (skb->pkt_type != 0 /* PACKET_HOST */ &&
		skb->pkt_type != 4 /* PACKET_OUTGOING */)
		return 0;

	// First pass: Quick filter to check if this is a DNS packet
	h_proto = load_half(skb, offsetof(struct ethhdr, h_proto));

	switch (h_proto) {
	case ETH_P_IP: {
		// Get IP protocol
		proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));

		// Calculate L4 offset - account for variable IP header length
		__u8 ihl_byte = load_byte(skb, ETH_HLEN);
		__u8 ip_header_len = (ihl_byte & 0x0F) * 4;
		l4_off = ETH_HLEN + ip_header_len;
		break;
	}
	case ETH_P_IPV6: {
		// Get next header (protocol)
		proto = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
		l4_off = ETH_HLEN + sizeof(struct ipv6hdr);

// Parse IPv6 extension headers (up to 6)
#pragma unroll
		for (int i = 0; i < 6; i++) {
			__u8 nextproto;

			// Stop if we found TCP or UDP
			if (proto == NEXTHDR_TCP || proto == NEXTHDR_UDP)
				break;

			nextproto = load_byte(skb, l4_off);

			switch (proto) {
			case NEXTHDR_FRAGMENT:
				l4_off += 8;
				break;
			case NEXTHDR_AUTH:
				l4_off += 4 * (load_byte(skb, l4_off + 1) + 2);
				break;
			case NEXTHDR_HOP:
			case NEXTHDR_ROUTING:
			case NEXTHDR_DEST:
				l4_off += 8 * (load_byte(skb, l4_off + 1) + 1);
				break;
			case NEXTHDR_NONE:
				return 0;
			default:
				return 0;
			}
			proto = nextproto;
		}
		break;
	}
	default:
		return 0;
	}

	// Check protocol is TCP or UDP
	if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
		return 0;

	// Extract ports (same offsets for UDP and TCP)
	sport = load_half(skb, l4_off + offsetof(struct udphdr, source));
	dport = load_half(skb, l4_off + offsetof(struct udphdr, dest));

	// Early exit if not DNS port
	if (!is_dns_port(sport) && !is_dns_port(dport))
		return 0;

	// Calculate DNS offset
	switch (proto) {
	case IPPROTO_UDP:
		dns_off = l4_off + sizeof(struct udphdr);
		break;
	case IPPROTO_TCP: {
		// Get TCP header length (data offset field)
		__u8 doff_byte =
			load_byte(skb, l4_off + 12); // Offset to data offset field
		__u8 tcp_header_len = ((doff_byte >> 4) & 0x0F) * 4;

		// Skip if no data (control segment)
		dns_off = l4_off + tcp_header_len;
		if (skb->len <= dns_off)
			return 0;

		// DNS over TCP has 2-byte length prefix
		dns_off += 2;
		break;
	}
	default:
		return 0;
	}

	// Look up index 0 of the per-CPU array to get a pointer to this CPU's
	// scratch buffer. The map only has one entry (max_entries=1), so index 0
	// is the only valid key. This returns a pointer the verifier trusts for
	// bounded writes, unlike a raw stack allocation.
	event = bpf_map_lookup_elem(&tmp_dns_events, &zero);
	if (!event)
		return 0;

	// Initialize event with zeros for fields that might be skipped
	__builtin_memset(event, 0, sizeof(*event));

	// Fill in event data
	event->timestamp = bpf_ktime_get_boot_ns();
	event->data_len = skb->len;
	event->dns_off = dns_off;
	event->pkt_type = skb->pkt_type;
	event->proto = proto;
	event->src_port = sport;
	event->dst_port = dport;

	// Extract IP addresses using bpf_skb_load_bytes for raw byte copy —
	// no byte-order conversion, so the Go side gets network-order bytes
	// that map directly to net.IP.
	switch (h_proto) {
	case ETH_P_IP:
		event->af = 4;
		bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
						   &event->src_ip, 4);
		bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
						   &event->dst_ip, 4);
		break;
	case ETH_P_IPV6:
		event->af = 6;
		bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
						   event->src_ip6, 16);
		bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
						   event->dst_ip6, 16);
		break;
	}

	// Bounds check: ensure DNS header (12 bytes) fits in packet
	if (skb->len < dns_off + sizeof(struct dnshdr))
		return 0;

	// Parse DNS flags manually with load_byte to avoid relying on the
	// dnsflags union bitfield layout, which is compiler-dependent.
	// DNS header bytes 2-3 (RFC 1035 §4.1.1):
	//   Byte 0: QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1)
	//   Byte 1: RA(1) | Z(3) | RCODE(4)
	__u8 flags0 = load_byte(skb, dns_off + 2);
	__u8 flags1 = load_byte(skb, dns_off + 3);
	event->qr = (flags0 >> 7) & 1;
	event->rcode = flags1 & 0x0F;
	event->id = load_half(skb, dns_off + offsetof(struct dnshdr, id));
	// load_half already applies ntohs — do NOT wrap with bpf_ntohs.
	event->ancount = load_half(skb, dns_off + offsetof(struct dnshdr, ancount));

	// Extract QTYPE from the first question. The question section starts
	// right after the 12-byte DNS header. The query name is encoded as
	// length-prefixed labels: [10]kubernetes[7]default[3]svc[0]
	// We walk past the name to reach the QTYPE field (2 bytes after the
	// terminating zero label).
	{
		__u16 qoff = dns_off + sizeof(struct dnshdr);
#pragma unroll
		for (int i = 0; i < 64; i++) {
			if (qoff >= skb->len)
				goto send;
			__u8 label_len = load_byte(skb, qoff);
			if (label_len == 0) {
				qoff += 1; // skip null terminator
				break;
			}
			qoff += 1 + label_len;
		}
		// QTYPE is a 2-byte field right after the name
		if (qoff + 2 <= skb->len)
			event->qtype = load_half(skb, qoff);
	}

send:
	// Send event + raw packet to userspace. The upper 32 bits of the flags
	// parameter tell the kernel how many bytes of packet data to append after
	// the event struct. The Go side uses this to parse the DNS payload.
	bpf_perf_event_output(skb, &retina_dns_events,
						  (__u64)skb->len << 32 | BPF_F_CURRENT_CPU, event,
						  sizeof(*event));

	return 0;
}
