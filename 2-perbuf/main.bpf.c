#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>

struct event
{
	int pid;
	char comm[256];
};

/* BPF perfbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx)
{
	struct event e = {};

	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, 256);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

char _license[] SEC("license") = "GPL";