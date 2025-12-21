//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define AF_INET 2
#define SO_ORIGINAL_DST 80
#define SOL_IP 0
#define ENVOY_MARK 4242
#define ENVOY_PORT 8080
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Map of open service ports that we listen on for requests
// TODO: is it possible to retrieve this from some kernel table
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // Port number
	__type(value, __u32); // Irrelevant
	__uint(max_entries, 1024);
} ports SEC(".maps");

struct tuple3 {
	__u32 ip4;
	__u32 port;
	__u32 proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuple3);
	__type(value, struct tuple3);
	__uint(max_entries, 65536);
} conntrack SEC(".maps");

SEC("tc")
int tc_both(struct __sk_buff* ctx) {
	// In case the traffic between envoy and the service goes through the same interface
	// to which the TC program is attached we need to avoid re-directing this traffic back to envoy (causing a loop).
	// We achieve this by marking.
	// An example would be attaching this program to `lo` interface and making the request from the same machine to
	// an endpoint on the localhost.
	__u32 so_mark = ctx->mark;
	if (so_mark == ENVOY_MARK) {
		//bpf_printk("Traffic from Envoy - don't re-redirect!");
		return TC_ACT_OK;
	}

	void* data_end = (void*) (unsigned long long) ctx->data_end;
	void* data = (void*) (unsigned long long) ctx->data;
	struct hdr_cursor nh;
	nh.pos = data;

	// Parse Ethernet header
	struct ethhdr* eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	// Parse IP header
	struct iphdr* ip;
	int ip_type = parse_iphdr(&nh, data_end, &ip);
	if (ip_type != IPPROTO_TCP) {
		return TC_ACT_OK;
	}
	if ((void*) (ip + 1) > data_end) {
		return TC_ACT_OK;
	}

	// Parse TCP header
	struct tcphdr* tcp;
	int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
	if ((void*) (tcp + 1) > data_end) {
		return TC_ACT_OK;
	}

	int csum_off = (int) ((void*) &tcp->check - data);

	// INGRESS
	if (ctx->ingress_ifindex) {
		// lookup if the queried port is actually listening
		// We do this to limit redirection to envoy only for requests to specific ports
		__u32 dst_port = bpf_ntohs(tcp->dest);
		__u32* val = bpf_map_lookup_elem(&ports, &dst_port);
		if (!val) {
			return TC_ACT_OK;
		}

		// Store original dst so Envoy can retrieve it later on egress as well as getsockopt:
		// * Key: client
		// * Value: original destination
		struct tuple3 client = {
			.ip4 = ip->saddr,
			.port = tcp->source,
			.proto = IPPROTO_TCP,
		};
		struct tuple3 orig_dst = {
			.ip4 = ip->daddr,
			.port = tcp->dest,
			.proto = IPPROTO_TCP,
		};
		int ret = bpf_map_update_elem(
			&conntrack, &client, &orig_dst, BPF_ANY);
		if (ret != 0) {
			return TC_ACT_OK;
		}

		// Store ports for TCP checksum recalculation
		__u16 old_dport = tcp->dest;
		__u16 new_dport = bpf_htons(ENVOY_PORT);

		// Redirect to envoy port
		tcp->dest = bpf_htons(ENVOY_PORT);

		// Recalculate TCP checksum
		bpf_l4_csum_replace(
			ctx, csum_off, old_dport, new_dport, sizeof(__be16));

	// EGRESS
	} else {
		__u32 src_port = bpf_ntohs(tcp->source);
		if (src_port == ENVOY_PORT) {
			struct tuple3 client = {
				.ip4 = ip->daddr,
				.port = tcp->dest,
				.proto = IPPROTO_TCP,
			};
			struct tuple3* orig_src = bpf_map_lookup_elem(&conntrack, &client);
			if (!orig_src) {
				return TC_ACT_OK;
			}

			// Store ports for TCP checksum recalculation
			__u16 old_sport = tcp->source;
			__u16 new_sport = orig_src->port;

			// Replace back the original destination port so client doesn't know it talks to the envoy
			tcp->source = orig_src->port;

			// Recalculate TCP checksum
			bpf_l4_csum_replace(ctx, csum_off, old_sport, new_sport,
				sizeof(__be16));
		}
	}

	return TC_ACT_OK;
}

SEC("cgroup/getsockopt")
int cg_getsockopt(struct bpf_sockopt* ctx)
{
	// TODO: Why check for SOL_IP
	if (!ctx->sk || ctx->level != SOL_IP ||
		ctx->optname != SO_ORIGINAL_DST) {
		return 1;
	}
	if (ctx->sk->family != AF_INET) {
		return 1;
	}

	// Key: client -> Value: Original destination
	struct tuple3 client = {
		.ip4 = ctx->sk->dst_ip4,
		.port = ctx->sk->dst_port,
		.proto = IPPROTO_TCP,
	};
	struct tuple3* orig_dst = bpf_map_lookup_elem(&conntrack, &client);
	if (!orig_dst) {
		return 1;
	}

	struct sockaddr_in* sa = (struct sockaddr_in*) ctx->optval;
	if ((void*) (sa + 1) > ctx->optval_end) {
		return 1;
	}

	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = orig_dst->ip4;
	sa->sin_port = orig_dst->port;

	ctx->optlen = sizeof(*sa);
	ctx->retval = 0; // pretend kernel provided it
	return 1; 
}

SEC("license") const char __license[] = "Dual BSD/GPL";
