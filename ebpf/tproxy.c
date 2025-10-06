//go:build ignore

#include "vmlinux.h" 
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define SO_ORIGINAL_DST 80

// Map of open service ports that we listen on for requests
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Port number
    __type(value, __u64); // Key for echo_socket eBPF map
    __uint(max_entries, 1024);
} echo_ports SEC(".maps");

// Map of socket to which the listening ports forward traffic (in our case only one)
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __type(key, __u32); // Port number
    __type(value, __u64); // Socket
    __uint(max_entries, 1);
} echo_socket SEC(".maps");

// Prevent proxy proxying itself 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // PID 
    __type(value, __u32); // irrelevant
    __uint(max_entries, 1);
} pid_map SEC(".maps");

struct orig_dst_key4 {
    __u32 client_ip4;   
    __u16 client_port; 
    __u8  proto;      
};

struct orig_dst_val4 {
    __u32 orig_ip4;  
    __u16 orig_port; 
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct orig_dst_key4);
    __type(value, struct orig_dst_val4);
    __uint(max_entries, 1024);
} orig_dst4 SEC(".maps");

// When invoked BPF sk_lookup program can select a socket that will receive the incoming packet 
// by calling the bpf_sk_assign() BPF helper function.
// Hooks for a common attach point (BPF_SK_LOOKUP) exist for both TCP and UDP.
SEC("sk_lookup/redirect")
int redirect(struct bpf_sk_lookup *ctx) {
	const __u32 zero = 0;
	
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 curr_tgid = pid_tgid >> 32;;

	// This prevents the proxy from proxying itself
	__u64 *pid = bpf_map_lookup_elem(&pid_map, &curr_tgid);
	if (pid) {
		return SK_PASS;
	}

	// Reads the packet’s destination (local) port and check against the map of ports being redirected
	__u32 port = ctx->local_port;
	__u32 *open = bpf_map_lookup_elem(&echo_ports, &port);
	if (!open) {
		return SK_PASS;
	}

	struct orig_dst_key4 k = {
		.client_ip4   = bpf_ntohl(ctx->remote_ip4),
		.client_port  = ctx->remote_port,
		.proto        = ctx->protocol,
	};
	struct orig_dst_val4 v = {
		.orig_ip4  = bpf_ntohl(ctx->local_ip4),
		.orig_port = ctx->local_port,
	};
	bpf_map_update_elem(&orig_dst4, &k, &v, BPF_ANY);

	// Get our envoy socket to redirect to
	// In our case we have only one socket in the map, but in general,
	// we could have multiple sockets and we would need to select the right one
	struct bpf_sock *sk = bpf_map_lookup_elem(&echo_socket, &zero);
	if (!sk) {
		return SK_DROP;
	}

	// Assign the received packet/request to the envoy socket
	long err = bpf_sk_assign(ctx, sk, 0);
	// Release the reference held by sock
	bpf_sk_release(sk);
	bpf_printk("redirecting..");

	// Selecting a socket only takes effect if the program has terminated with SK_PASS code.
	return err ? SK_DROP : SK_PASS;
}

SEC("cgroup/getsockopt")
int cg_getsockopt(struct bpf_sockopt *ctx) {
	if (!ctx->sk || ctx->optname != SO_ORIGINAL_DST) {
		return 1;
	}
	if (ctx->sk->family != AF_INET) {
		return 1;
	}

	struct orig_dst_key4 k = {
		.client_ip4   = ctx->sk->src_ip4,         // host order
		.client_port  = ctx->sk->src_port,        // host order
		.proto        = ctx->sk->protocol,        // TCP/UDP
	};
	struct orig_dst_val4 *v = bpf_map_lookup_elem(&orig_dst4, &k);
	if (!v) {
		return 1;
	}

	struct sockaddr_in *sa = (struct sockaddr_in *)ctx->optval;
	if ((void*)(sa + 1) > ctx->optval_end) {
		return 1;
	}

	sa->sin_family      = AF_INET;
	sa->sin_addr.s_addr = bpf_htonl(v->orig_ip4);
	sa->sin_port        = bpf_htons(v->orig_port);

	ctx->optlen = sizeof(*sa);
	ctx->retval = 0;   // pretend kernel provided it
	return 1;          // allow; retval already set
}


SEC("license") const char __license[] = "Dual BSD/GPL";
