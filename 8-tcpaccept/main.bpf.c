#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "../common.h"

struct sock_key
{
    __u32 sip;    //源IP
    __u32 dip;    //目的IP
    __u32 sport;  //源端口
    __u32 dport;  //目的端口
    __u32 family; //协议
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

SEC("kretprobe/inet_csk_accept")
int kb_tcp_accept(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *) PT_REGS_RET(ctx);
	struct sock_key *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
	{
		return 0;
	}


	struct sock_common sk_common = READ_KERN(sk->__sk_common);
	event->dip = READ_KERN(sk_common.skc_daddr);
	event->sip = READ_KERN(sk_common.skc_rcv_saddr);
	event->sport = READ_KERN(sk_common.skc_num);
	event->dport = bpf_ntohs(READ_KERN(sk_common.skc_dport));
	event->family = READ_KERN(sk_common.skc_family);
	
	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";