#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * oom_kill_process fires when the OOM killer terminates a task. We emit
 * a single PNET_EVENT_OOM event carrying the victim task's cgroup id so
 * userspace can attribute the kill to a container.
 *
 * The current task (and bpf_get_current_cgroup_id()) belongs to whoever
 * tripped the OOM killer, which is NOT necessarily the victim. We walk
 * the victim task_struct -> cgroups -> dfl_cgrp -> kn.id chain so the
 * cgroup_id we report matches what the victim container observes via
 * bpf_get_current_cgroup_id() in the rest of the BPF stack.
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
	event->pid = bpf_get_current_pid_tgid() >> 32;

	BPF_CORE_READ_INTO(&victim, oc, chosen);
	if (victim) {
		__u32 vpid = 0;
		BPF_CORE_READ_INTO(&vpid, victim, tgid);
		event->victim_pid = vpid;

		__u64 vcgid = BPF_CORE_READ(victim, cgroups, dfl_cgrp, kn, id);
		if (vcgid)
			event->cgroup_id = vcgid;
	}
	if (event->cgroup_id == 0)
		event->cgroup_id = current_cgroup_id();

	bpf_ringbuf_submit(event, 0);
	return 0;
}
