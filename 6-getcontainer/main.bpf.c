#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common.h"

struct event_t
{
	u32 host_pid;	 // pid in host pid namespace
	u32 host_ppid; // ppid in host pid namespace

	char nodename[65];
	char comm[100]; // the name of the executable (excluding the path)
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event_t *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
	{
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent_task = READ_KERN(task->real_parent);
	u64 tgid = bpf_get_current_pid_tgid();
	event->host_pid = tgid >> 32;
	event->host_ppid = READ_KERN(parent_task->tgid);

	struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
  char *uts_name = READ_KERN(READ_KERN(namespaceproxy->uts_ns)->name.nodename);
	bpf_probe_read_str(&event->nodename, 65, uts_name);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";