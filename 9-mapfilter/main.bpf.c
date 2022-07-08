#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../common.h"

struct event
{
	u32 pid;
	char comm[16];
	char file[256];
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

/* BPF_MAP_TYPE_HASH */
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1024 * 16 /* number */);
} pid_filter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{
	u32 firstKey = 1;
	u32 *pidFilter;
	pidFilter = bpf_map_lookup_elem(&pid_filter, &firstKey);

	if (!pidFilter)
	{
		return 0;
	}

	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (*pidFilter != 0 && *pidFilter != pid)
	{
		return 0;
	}

	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
	{
		return 0;
	}

	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->file, sizeof(e->file), (char *)(ctx->args[1]));
	bpf_ringbuf_submit(e, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";