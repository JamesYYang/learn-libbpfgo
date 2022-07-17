#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "../common.h"

struct sock_key
{
	__u32 sip;		//源IP
	__u32 dip;		//目的IP
	__u32 sport;	//源端口
	__u32 dport;	//目的端口
	__u32 family; //协议
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

/*
 * Insert socket into sockmap
 */
static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops, struct sock_key *key)
{
	// keep ip and port in network byte order
	key->dip = skops->remote_ip4;
	key->sip = skops->local_ip4;
	key->family = 1;

	// local_port is in host byte order, and
	// remote_port is in network byte order
	key->sport = bpf_htonl(skops->local_port);
	key->dport = skops->remote_port;
}

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	switch (skops->op)
	{
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (skops->family == 2)
		{ // AF_INET
			struct sock_key *event;
			event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
			if (!event)
			{
				return 0;
			}
			bpf_sock_ops_ipv4(skops, event);
			bpf_ringbuf_submit(event, 0);
		}
		break;
	default:
		break;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";