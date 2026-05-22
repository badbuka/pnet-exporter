#ifndef PNET_EXPORTER_COMMON_H
#define PNET_EXPORTER_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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

/*
 * struct tcp_event is the legacy 72-byte event used by tcp_state,
 * tcp_retransmit and tcp_bytes programs. Layout is documented in
 * internal/ebpf/events.go.
 */
struct tcp_event {
	__u8 kind;
	__u64 cgroup_id;
	__u32 pid;
	struct socket_tuple tuple;
	__u64 value;
};

/*
 * struct nat_event is emitted by tcp_conntrack and carries both the
 * pre-NAT (orig) and post-NAT (reply) tuples. Userspace inverts the
 * reply tuple to derive the actual destination an outbound connection
 * landed on.
 */
struct nat_event {
	__u8 kind;
	__u8 _pad0[7];
	__u64 cgroup_id;
	__u32 pid;
	struct socket_tuple orig;
	struct socket_tuple reply;
};

/*
 * struct l7_event carries up to 256 bytes of an outbound or inbound
 * TCP payload along with the duration the userspace side will use to
 * derive a request/response histogram.
 */
struct l7_event {
	__u8 kind;
	__u8 direction;
	__u16 payload_len;
	__u8 _pad0[4];
	__u64 cgroup_id;
	__u32 pid;
	struct socket_tuple tuple;
	__u8 _pad1[6];
	__u64 elapsed_ns;
	__u8 payload[PNET_L7_PAYLOAD_BYTES];
};

/*
 * struct dns_event mirrors l7_event but carries a larger payload window
 * suited to typical DNS packets.
 */
struct dns_event {
	__u8 kind;
	__u8 direction;
	__u16 payload_len;
	__u8 _pad0[4];
	__u64 cgroup_id;
	__u32 pid;
	struct socket_tuple tuple;
	__u8 _pad1[6];
	__u8 payload[PNET_DNS_PAYLOAD_BYTES];
};

/*
 * struct oom_event is emitted when the OOM killer terminates a task.
 */
struct oom_event {
	__u8 kind;
	__u8 _pad0[7];
	__u64 cgroup_id;
	__u32 pid;
	__u32 victim_pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline __u64 current_cgroup_id(void)
{
	return bpf_get_current_cgroup_id();
}

/*
 * Pre-6.4 kernels named the iovec pointer in struct iov_iter `iov`;
 * kernel 6.4 renamed it to `__iov` (commit fcb14cb1bdac). We can't
 * depend on the build-time vmlinux.h having either name, so declare
 * CO-RE flavors that expose each one and let bpf_core_field_exists()
 * pick the right path at load time. libbpf strips the ___suffix when
 * resolving these against the running kernel's struct iov_iter BTF.
 */
struct iov_iter___pnet_old {
	const struct iovec *iov;
} __attribute__((preserve_access_index));

struct iov_iter___pnet_new {
	const struct iovec *__iov;
} __attribute__((preserve_access_index));

static __always_inline const struct iovec *
pnet_msghdr_iov(struct msghdr *msg)
{
	const struct iovec *iov = NULL;
	void *it = (void *)&msg->msg_iter;

	if (bpf_core_field_exists(((struct iov_iter___pnet_old *)0)->iov)) {
		iov = BPF_CORE_READ((struct iov_iter___pnet_old *)it, iov);
	} else if (bpf_core_field_exists(((struct iov_iter___pnet_new *)0)->__iov)) {
		iov = BPF_CORE_READ((struct iov_iter___pnet_new *)it, __iov);
	}
	return iov;
}

#endif
