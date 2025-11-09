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
  __type(key, __u32);   // Port number
  __type(value, __u32); // Irrelevant
  __uint(max_entries, 1024);
} ports SEC(".maps");

struct orig_dst_key4 {
  __u32 client_ip4;
  __u32 client_port;
  __u32 proto;
};

struct orig_dst_val4 {
  __u32 orig_ip4;
  __u32 orig_port;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct orig_dst_key4);
  __type(value, struct orig_dst_val4);
  __uint(max_entries, 1024);
} orig_dst4 SEC(".maps");

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {
  // Read skb mark (this is what SO_MARK on the socket gets copied to)
  __u32 so_mark = ctx->mark;
  if (so_mark == ENVOY_MARK) {
    bpf_printk("Traffic from Envoy - don't redirect on ingress!");
    return TC_ACT_OK;
  }

  void *data_end = (void *)(unsigned long long)ctx->data_end;
  void *data = (void *)(unsigned long long)ctx->data;
  struct hdr_cursor nh;
  nh.pos = data;

  // Parse Ethernet and IP headers
  int ip_type;
  struct iphdr *ip;
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type == bpf_htons(ETH_P_IP)) {
    ip_type = parse_iphdr(&nh, data_end, &ip);
  } else {
    // Default action, pass it up the GNU/Linux network stack to be handled
    return TC_ACT_OK;
  }

  // If not TCP Protocol -> TC_ACT_OK
  if (ip_type != IPPROTO_TCP) {
    return TC_ACT_OK;
  }

  if ((void *)(ip + 1) > data_end) {
    return TC_ACT_OK;
  }

  struct tcphdr *tcp;
  int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end) {
    return TC_ACT_OK;
  }

  // lookup if the queried port is actually listening
  __u32 dst_port = bpf_ntohs(tcp->dest);
  __u32 *val = bpf_map_lookup_elem(&ports, &dst_port);
  if (!val) {
    return TC_ACT_OK;
  }

  // Store original dst so Envoy can retrieve it later via getsockopt
  struct orig_dst_key4 k = {
      .client_ip4 = bpf_ntohl(ip->saddr), // client = src of incoming packet
      .client_port = ENVOY_PORT,          // host order
      .proto = IPPROTO_TCP,
  };
  struct orig_dst_val4 v = {
      .orig_ip4 = bpf_ntohl(ip->daddr),  // original dst before redirect
      .orig_port = bpf_ntohs(tcp->dest), // host order
  };

  int ret = bpf_map_update_elem(&orig_dst4, &k, &v, BPF_ANY);
  if (ret != 0) {
    return TC_ACT_OK;
  }

  // Redirect and recalculate TCP checksum
  int diff = bpf_htons(tcp->dest) - bpf_htons(ENVOY_PORT);
  tcp->dest =
      bpf_htons(ENVOY_PORT); // Change the destination port to Envoy proxy port
  tcp->check += bpf_htons(diff);
  // TODO: is this necessary?
  if (!tcp->check) {
    tcp->check += bpf_htons(diff);
  }
  // Print human-readable info (IPv4 addresses in dotted form)
  bpf_printk("client: %d.%d.%d.%d:%d -> orig: %d.%d.%d.%d:%d proto=%d",
             (k.client_ip4 >> 24) & 0xff, (k.client_ip4 >> 16) & 0xff,
             (k.client_ip4 >> 8) & 0xff, k.client_ip4 & 0xff,  bpf_ntohs(tcp->source),
             (v.orig_ip4 >> 24) & 0xff, (v.orig_ip4 >> 16) & 0xff,
             (v.orig_ip4 >> 8) & 0xff, v.orig_ip4 & 0xff, bpf_ntohs(tcp->dest), k.proto);
  bpf_printk("Redirecting in TC ingress...");
  bpf_printk("========================================");

  return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx) {
  // Read skb mark (this is what SO_MARK on the socket gets copied to)
  __u32 so_mark = ctx->mark;
  if (so_mark == ENVOY_MARK) {
    bpf_printk("Traffic from Envoy - don't redirect on egress!");
    return TC_ACT_OK;
  }

  void *data_end = (void *)(unsigned long long)ctx->data_end;
  void *data = (void *)(unsigned long long)ctx->data;
  struct hdr_cursor nh;
  nh.pos = data;

  // Parse Ethernet and IP headers
  int ip_type;
  struct iphdr *ip;
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type == bpf_htons(ETH_P_IP)) {
    ip_type = parse_iphdr(&nh, data_end, &ip);
  } else {
    // Default action, pass it up the GNU/Linux network stack to be handled
    return TC_ACT_OK;
  }

  // If not TCP Protocol -> TC_ACT_OK
  if (ip_type != IPPROTO_TCP) {
    return TC_ACT_OK;
  }

  if ((void *)(ip + 1) > data_end) {
    return TC_ACT_OK;
  }

  struct tcphdr *tcp;
  int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end) {
    return TC_ACT_OK;
  }

  // lookup if the destination is in the eBPF map
  __u32 src_port = bpf_ntohs(tcp->source);
  if (src_port == ENVOY_PORT) {
    // Redirect and recalculate TCP checksum
    int diff = bpf_htons(tcp->source) - bpf_htons(80);
    tcp->source = bpf_htons(80); // Change the destination port to original port
    tcp->check += bpf_htons(diff);
    // TODO: is this necessary?
    if (!tcp->check) {
      tcp->check += bpf_htons(diff);
    }
    bpf_printk("Redirecting on egress...");
    bpf_printk("========================================");
  }

  return TC_ACT_OK;
}

SEC("cgroup/getsockopt")
int cg_getsockopt(struct bpf_sockopt *ctx) {
  // TODO: Why check for SOL_IP
  if (!ctx->sk || ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
    return 1;
  }
  if (ctx->sk->family != AF_INET) {
    return 1;
  }

  bpf_printk("getsockopt: src_port=%d dst_port=%d", ctx->sk->src_port,
             ctx->sk->dst_port);
  struct orig_dst_key4 k = {
      .client_ip4 = bpf_ntohl(ctx->sk->src_ip4), // host order
      .client_port = ctx->sk->src_port,          // host order
      .proto = ctx->sk->protocol,                // TCP/UDP
  };
  bpf_printk("getsockopt key: src_ip4=%d.%d.%d.%d src_port=%d proto=%d\n",
             (k.client_ip4 >> 24) & 0xff, (k.client_ip4 >> 16) & 0xff,
             (k.client_ip4 >> 8) & 0xff, k.client_ip4 & 0xff, k.client_port,
             k.proto);
  struct orig_dst_val4 *v = bpf_map_lookup_elem(&orig_dst4, &k);
  if (!v) {
    return 1;
  }

  struct sockaddr_in *sa = (struct sockaddr_in *)ctx->optval;
  if ((void *)(sa + 1) > ctx->optval_end) {
    return 1;
  }

  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = bpf_htonl(v->orig_ip4);
  sa->sin_port = bpf_htons(v->orig_port);

  ctx->optlen = sizeof(*sa);
  ctx->retval = 0; // pretend kernel provided it
  bpf_printk("Retrieved original destination...");
  return 1; // allow; retval already set
}

SEC("license") const char __license[] = "Dual BSD/GPL";
