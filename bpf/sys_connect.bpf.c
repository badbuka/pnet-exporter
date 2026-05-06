#include "common.h"

struct connect_key {
	__u64 pid_tgid;
	__u64 cgroup_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct connect_key);
	__type(value, struct socket_tuple);
} original_destinations SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct connect_key key = {
		.pid_tgid = bpf_get_current_pid_tgid(),
		.cgroup_id = current_cgroup_id(),
	};
	struct socket_tuple tuple = {};

	bpf_map_update_elem(&original_destinations, &key, &tuple, BPF_ANY);
	return 0;
}
