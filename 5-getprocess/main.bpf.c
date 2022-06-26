#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common.h"

struct event_t
{
	u64 cgroup_id; // cgroup id
	u32 host_tid;	 // tid in host pid namespace
	u32 host_pid;	 // pid in host pid namespace
	u32 host_ppid; // ppid in host pid namespace

	u32 tid;	// thread id in userspace
	u32 pid;	// process id in userspace
	u32 ppid; // parent process id in userspace
	u32 uid;
	u32 gid;

	u32 cgroup_ns_id;
	u32 ipc_ns_id;
	u32 net_ns_id;
	u32 mount_ns_id;
	u32 pid_ns_id;
	u32 time_ns_id;
	u32 user_ns_id;
	u32 uts_ns_id;

	char comm[25]; // the name of the executable (excluding the path)
};

struct event
{
	int pid;
	char filename[256];
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
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
	u64 ugid = bpf_get_current_uid_gid();

	event->cgroup_id = bpf_get_current_cgroup_id();
	event->host_tid = tgid;
	event->host_pid = tgid >> 32;

	event->host_ppid = READ_KERN(parent_task->tgid);

	struct nsproxy *namespaceproxy = READ_KERN(task->nsproxy);
	struct pid_namespace *pid_ns_children = READ_KERN(namespaceproxy->pid_ns_for_children);
	unsigned int level = READ_KERN(pid_ns_children->level);
	event->tid = READ_KERN(READ_KERN(task->thread_pid)->numbers[level].nr);

	event->pid = READ_KERN(READ_KERN(READ_KERN(task->group_leader)->thread_pid)->numbers[level].nr);
	struct nsproxy *parent_namespaceproxy = READ_KERN(parent_task->nsproxy);
	struct pid_namespace *parent_pid_ns_children = READ_KERN(parent_namespaceproxy->pid_ns_for_children);
	unsigned int parent_level = READ_KERN(parent_pid_ns_children->level);
	event->ppid = READ_KERN(READ_KERN(READ_KERN(parent_task->group_leader)->thread_pid)->numbers[parent_level].nr);

	event->uid = ugid;
	event->gid = ugid >> 32;

	event->cgroup_ns_id = READ_KERN(READ_KERN(namespaceproxy->cgroup_ns)->ns.inum);
	event->ipc_ns_id = READ_KERN(READ_KERN(namespaceproxy->ipc_ns)->ns.inum);
	event->net_ns_id = READ_KERN(READ_KERN(namespaceproxy->net_ns)->ns.inum);
	event->mount_ns_id = READ_KERN(READ_KERN(namespaceproxy->mnt_ns)->ns.inum);
	event->pid_ns_id = READ_KERN(READ_KERN(namespaceproxy->pid_ns_for_children)->ns.inum);
	event->time_ns_id = READ_KERN(READ_KERN(namespaceproxy->time_ns)->ns.inum);
	event->user_ns_id = READ_KERN(READ_KERN(namespaceproxy->cgroup_ns)->ns.inum);
	event->uts_ns_id = READ_KERN(READ_KERN(namespaceproxy->cgroup_ns)->ns.inum);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_ringbuf_submit(event, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";