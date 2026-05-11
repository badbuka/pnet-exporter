#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * dns captures up to PNET_DNS_PAYLOAD_BYTES bytes of each UDP send and
 * receive so user-space can parse DNS queries/responses. Same iov-walk
 * caveats as the L7 program apply.
 */

static __always_inline void fill_tuple(struct socket_tuple *st, struct sock *sk)
{
	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	st->family = family;
	__u16 sport = 0;
	__be16 dport = 0;
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	st->sport = sport;
	st->dport = bpf_ntohs(dport);
	if (family == AF_INET_VALUE) {
		__be32 saddr = 0, daddr = 0;
		BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
		__builtin_memcpy(st->saddr, &saddr, 4);
		__builtin_memcpy(st->daddr, &daddr, 4);
	} else if (family == AF_INET6_VALUE) {
		BPF_CORE_READ_INTO(st->saddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(st->daddr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

static __always_inline int copy_dns_payload(struct msghdr *msg, __u8 *dst,
					    __u16 *out_len)
{
	const struct iovec *iov = NULL;
	__u64 nr = 0;

	if (BPF_CORE_READ_INTO(&nr, msg, msg_iter.nr_segs) || nr == 0)
		return -1;
	if (BPF_CORE_READ_INTO(&iov, msg, msg_iter.__iov) || !iov)
		return -1;

	__u64 base = 0;
	__u64 len = 0;
	bpf_probe_read_kernel(&base, sizeof(base), &iov->iov_base);
	bpf_probe_read_kernel(&len, sizeof(len), &iov->iov_len);
	if (base == 0 || len == 0)
		return -1;
	if (len > PNET_DNS_PAYLOAD_BYTES)
		len = PNET_DNS_PAYLOAD_BYTES;
	if (bpf_probe_read_user(dst, len, (const void *)(unsigned long)base) < 0)
		return -1;
	*out_len = (__u16)len;
	return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(dns_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct dns_event *event;
	if (!sk || !msg)
		return 0;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event));
	event->kind = PNET_EVENT_DNS;
	event->direction = PNET_DIR_REQUEST;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	fill_tuple(&event->tuple, sk);
	if (copy_dns_payload(msg, event->payload, &event->payload_len) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(dns_udp_recvmsg, struct sock *sk, struct msghdr *msg)
{
	struct dns_event *event;
	if (!sk || !msg)
		return 0;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event));
	event->kind = PNET_EVENT_DNS;
	event->direction = PNET_DIR_RESPONSE;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	fill_tuple(&event->tuple, sk);
	if (copy_dns_payload(msg, event->payload, &event->payload_len) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}
