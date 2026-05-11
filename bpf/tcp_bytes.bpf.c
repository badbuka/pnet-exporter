#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * tcp_sendmsg fires for every successful send on a TCP socket. The size
 * argument is the number of bytes the caller asked the kernel to send.
 * We attribute it as PNET_EVENT_TCP_BYTES_SENT for the (peer) tuple
 * derived from the sock's inet_sock fields.
 */
static __always_inline void emit_bytes(struct sock *sk, size_t size, __u8 kind)
{
	struct tcp_event *event;
	__u16 family = 0;

	if (!sk)
		return;

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	if (family != AF_INET_VALUE && family != AF_INET6_VALUE)
		return;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return;

	__builtin_memset(event, 0, sizeof(*event));
	event->kind = kind;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tuple.family = family;
	event->value = (__u64)size;

	__u16 sport = 0, dport = 0;
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	event->tuple.sport = sport;
	event->tuple.dport = bpf_ntohs(dport);

	if (family == AF_INET_VALUE) {
		__be32 saddr = 0, daddr = 0;
		BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
		__builtin_memcpy(event->tuple.saddr, &saddr, 4);
		__builtin_memcpy(event->tuple.daddr, &daddr, 4);
	} else {
		BPF_CORE_READ_INTO(event->tuple.saddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(event->tuple.daddr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}

	bpf_ringbuf_submit(event, 0);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, struct sock *sk, struct msghdr *msg,
	       size_t size)
{
	emit_bytes(sk, size, PNET_EVENT_TCP_BYTES_SENT);
	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;
	emit_bytes(sk, (size_t)copied, PNET_EVENT_TCP_BYTES_RECEIVED);
	return 0;
}
