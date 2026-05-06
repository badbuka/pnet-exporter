#include "common.h"

struct protocol_event {
	__u8 protocol;
	__u64 cgroup_id;
	__u32 pid;
	struct socket_tuple tuple;
	__u64 correlation_id;
	__u64 duration_ns;
	__s32 status;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} protocol_events SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("socket")
int classify_protocol_packet(struct __sk_buff *skb)
{
	(void)skb;
	return 0;
}
