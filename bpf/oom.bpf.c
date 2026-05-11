#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * oom_kill_process fires when the OOM killer terminates a task. We emit
 * a single PNET_EVENT_OOM event carrying the victim task's cgroup id so
 * userspace can attribute the kill to a container.
 */
SEC("kprobe/oom_kill_process")
int BPF_KPROBE(handle_oom_kill_process, struct oom_control *oc)
{
	struct oom_event *event;
	struct task_struct *victim = NULL;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	event->kind = PNET_EVENT_OOM;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;

	BPF_CORE_READ_INTO(&victim, oc, chosen);
	if (victim) {
		__u32 vpid = 0;
		BPF_CORE_READ_INTO(&vpid, victim, tgid);
		event->victim_pid = vpid;
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}
