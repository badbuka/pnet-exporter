#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * tcp_inbound tracks server-side (accepted) TCP sockets so user-space can
 * expose inbound traffic separately from the outbound-centric metrics.
 *
 * inbound_socks remembers every socket returned by inet_csk_accept (i.e.
 * connections a server inside a container accepted). Membership lets the
 * byte hooks attribute send/receive traffic to the inbound metrics and
 * lets tcp_close decrement the inbound active-connections gauge. Keying on
 * the struct sock pointer keeps the map self-contained within this object,
 * so no cross-object map sharing is required.
 *
 * For an accepted socket the kernel sock has the local listen address in
 * skc_rcv_saddr/skc_num and the remote client in skc_daddr/skc_dport, so
 * the client lands in tuple.daddr:dport and is exposed as the `source`
 * label by user-space.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 65536);
} inbound_socks SEC(".maps");

static __always_inline void fill_inbound_tuple(struct socket_tuple *st,
					       struct sock *sk)
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

static __always_inline void emit_inbound(struct sock *sk, __u8 kind,
					 __u64 value)
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
	event->value = value;
	fill_inbound_tuple(&event->tuple, sk);

	bpf_ringbuf_submit(event, 0);
}

/*
 * inet_csk_accept returns the newly accepted child socket. It runs in the
 * accepting process context so cgroup/pid attribution matches the server
 * container.
 */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_inet_csk_accept, struct sock *sk)
{
	__u64 key;
	__u8 one = 1;

	if (!sk)
		return 0;

	key = (__u64)sk;
	bpf_map_update_elem(&inbound_socks, &key, &one, BPF_ANY);
	emit_inbound(sk, PNET_EVENT_TCP_INBOUND_ACCEPT, 1);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_inbound_sendmsg, struct sock *sk, struct msghdr *msg,
	       size_t size)
{
	__u64 key = (__u64)sk;
	if (!sk || !bpf_map_lookup_elem(&inbound_socks, &key))
		return 0;
	emit_inbound(sk, PNET_EVENT_TCP_INBOUND_BYTES_SENT, (__u64)size);
	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_inbound_cleanup_rbuf, struct sock *sk, int copied)
{
	__u64 key = (__u64)sk;
	if (copied <= 0)
		return 0;
	if (!sk || !bpf_map_lookup_elem(&inbound_socks, &key))
		return 0;
	emit_inbound(sk, PNET_EVENT_TCP_INBOUND_BYTES_RECEIVED,
		     (__u64)copied);
	return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_inbound_close, struct sock *sk)
{
	__u64 key = (__u64)sk;
	if (!sk || !bpf_map_lookup_elem(&inbound_socks, &key))
		return 0;
	emit_inbound(sk, PNET_EVENT_TCP_INBOUND_CLOSE, 1);
	bpf_map_delete_elem(&inbound_socks, &key);
	return 0;
}
