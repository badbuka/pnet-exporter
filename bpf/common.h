#ifndef PNET_EXPORTER_COMMON_H
#define PNET_EXPORTER_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "events.h"

#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10

struct socket_tuple {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 sport;
	__u16 dport;
	__u16 family;
};

struct tcp_event {
	__u8 kind;
	__u64 cgroup_id;
	__u32 pid;
	struct socket_tuple tuple;
	__u64 value;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline __u64 current_cgroup_id(void)
{
	return bpf_get_current_cgroup_id();
}

#endif
