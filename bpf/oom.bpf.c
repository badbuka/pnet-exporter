#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Local CO-RE flavors for the task_struct -> cgroups -> dfl_cgrp ->
 * kn -> id chain. The libbpf/vmlinux.h snapshot used in the Docker
 * build is generated from a kernel that drops some of these fields
 * (e.g. struct task_struct here lacks 'cgroups'), so we can't rely on
 * vmlinux.h to declare them. The '___pnet' suffix is stripped by
 * libbpf when resolving field offsets against the running kernel's
 * BTF, so each flavor maps to its canonical kernel counterpart at
 * load time.
 *
 * Pre-5.5 kernels also declared kernfs_node.id as a union; declaring
 * the flavor here forces a __u64 view that BPF_CORE_READ can
 * relocate uniformly across both layouts.
 */
struct kernfs_node___pnet {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup___pnet {
	struct kernfs_node___pnet *kn;
} __attribute__((preserve_access_index));

struct css_set___pnet {
	struct cgroup___pnet *dfl_cgrp;
} __attribute__((preserve_access_index));

struct task_struct___pnet {
	struct css_set___pnet *cgroups;
} __attribute__((preserve_access_index));

static __always_inline __u64 task_cgroup_id(struct task_struct *task)
{
	struct task_struct___pnet *t = (struct task_struct___pnet *)task;
	struct kernfs_node___pnet *kn;

	kn = BPF_CORE_READ(t, cgroups, dfl_cgrp, kn);
	if (!kn)
		return 0;
	return BPF_CORE_READ(kn, id);
}

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

		__u64 vcgid = task_cgroup_id(victim);
		if (vcgid)
			event->cgroup_id = vcgid;
	}
	if (event->cgroup_id == 0)
		event->cgroup_id = current_cgroup_id();

	bpf_ringbuf_submit(event, 0);
	return 0;
}
