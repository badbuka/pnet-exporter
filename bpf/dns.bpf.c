#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * dns captures up to PNET_DNS_PAYLOAD_BYTES bytes of each UDP send and
 * receive so user-space can parse DNS queries/responses. Same iov-walk
 * caveats as the L7 program apply.
 *
 * udp_sendmsg can be captured at kprobe entry (the user-space query is
 * already populated in msg->iov), but udp_recvmsg MUST be captured at
 * kretprobe: at entry the user buffer is still empty and the response
 * bytes only land in it after the kernel finishes copying. We stash the
 * sk/msg pointers per pid_tgid on entry and consume them on return.
 */

struct dns_recv_args {
	struct sock *sk;
	struct msghdr *msg;
	__u64 iov_base;
	__u64 iov_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct dns_recv_args);
	__uint(max_entries, 4096);
} dns_active_recv SEC(".maps");

/*
 * Local mirrors of the kernel's sockaddr_in / sockaddr_in6. Layouts
 * match the UAPI definitions exactly (size 16 and 28 respectively with
 * natural alignment), so a single bpf_probe_read_kernel pulls out
 * family/port/address in one go.
 */
struct pnet_sockaddr_in {
	__u16 sin_family;
	__be16 sin_port;
	__be32 sin_addr;
	__u8 sin_zero[8];
};

struct pnet_sockaddr_in6 {
	__u16 sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	__u8 sin6_addr[16];
	__u32 sin6_scope_id;
};

/*
 * fill_local populates the local (bound) side of the tuple from the
 * sock. DNS clients typically bind to an ephemeral port on the wildcard
 * address, so these fields are always meaningful.
 */
static __always_inline __u16 fill_local(struct socket_tuple *st,
					struct sock *sk)
{
	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	st->family = family;

	__u16 sport = 0;
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	st->sport = sport;

	if (family == AF_INET_VALUE) {
		__be32 saddr = 0;
		BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(st->saddr, &saddr, 4);
	} else if (family == AF_INET6_VALUE) {
		BPF_CORE_READ_INTO(st->saddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
	return family;
}

/*
 * fill_peer_from_sock falls back to the sock's connected-peer fields.
 * For unconnected UDP (the common DNS case) these are zero, so the
 * caller must first try msg->msg_name via fill_peer_from_msg.
 */
static __always_inline void fill_peer_from_sock(struct socket_tuple *st,
						struct sock *sk, __u16 family)
{
	__be16 dport = 0;
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	st->dport = bpf_ntohs(dport);
	if (family == AF_INET_VALUE) {
		__be32 daddr = 0;
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
		__builtin_memcpy(st->daddr, &daddr, 4);
	} else if (family == AF_INET6_VALUE) {
		BPF_CORE_READ_INTO(st->daddr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
}

/*
 * fill_peer_from_msg reads the remote peer from msg->msg_name. On the
 * send path msg_name is the user-supplied destination (sendto); on the
 * recv path the kernel populates msg_name with the sender's address
 * before udp_recvmsg returns. Returns true if a peer was extracted.
 */
static __always_inline int fill_peer_from_msg(struct socket_tuple *st,
					      struct msghdr *msg)
{
	void *name = NULL;
	int namelen = 0;

	BPF_CORE_READ_INTO(&name, msg, msg_name);
	BPF_CORE_READ_INTO(&namelen, msg, msg_namelen);
	if (!name || namelen <= 0)
		return 0;

	__u16 fam = 0;
	if (bpf_probe_read_kernel(&fam, sizeof(fam), name) < 0)
		return 0;

	if (fam == AF_INET_VALUE) {
		struct pnet_sockaddr_in sin = {};
		if (bpf_probe_read_kernel(&sin, sizeof(sin), name) < 0)
			return 0;
		st->dport = bpf_ntohs(sin.sin_port);
		__builtin_memcpy(st->daddr, &sin.sin_addr, 4);
		return 1;
	}
	if (fam == AF_INET6_VALUE) {
		struct pnet_sockaddr_in6 sin6 = {};
		if (bpf_probe_read_kernel(&sin6, sizeof(sin6), name) < 0)
			return 0;
		st->dport = bpf_ntohs(sin6.sin6_port);
		__builtin_memcpy(st->daddr, sin6.sin6_addr, 16);
		return 1;
	}
	return 0;
}

/*
 * fill_tuple populates both sides of the tuple. The local side always
 * comes from the sock; the remote side comes from msg->msg_name when
 * the socket is unconnected (the typical DNS case) and from the sock's
 * connected peer fields otherwise.
 */
static __always_inline void fill_tuple(struct socket_tuple *st,
				       struct sock *sk, struct msghdr *msg)
{
	__u16 family = fill_local(st, sk);
	if (msg && fill_peer_from_msg(st, msg))
		return;
	fill_peer_from_sock(st, sk, family);
}

/*
 * copy_dns_payload reads up to PNET_DNS_PAYLOAD_BYTES bytes from the
 * first iovec backing `msg`. max_len caps the read to the number of
 * bytes the kernel actually intends to send (udp_sendmsg `size` arg)
 * or actually received (udp_recvmsg return value); pass 0 to fall back
 * to iov->iov_len.
 */
static __always_inline int copy_dns_payload(struct msghdr *msg, __u8 *dst,
					    __u16 *out_len, __u32 max_len)
{
	const struct iovec *iov = NULL;
	__u64 nr = 0;

	if (BPF_CORE_READ_INTO(&nr, msg, msg_iter.nr_segs) || nr == 0)
		return -1;
	iov = pnet_msghdr_iov(msg);
	if (!iov)
		return -1;

	__u64 base = 0;
	__u64 len = 0;
	bpf_probe_read_kernel(&base, sizeof(base), &iov->iov_base);
	bpf_probe_read_kernel(&len, sizeof(len), &iov->iov_len);
	if (base == 0 || len == 0)
		return -1;
	if (max_len > 0 && (__u64)max_len < len)
		len = max_len;
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
	fill_tuple(&event->tuple, sk, msg);
	if (copy_dns_payload(msg, event->payload, &event->payload_len,
			     (__u32)size) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(dns_udp_recvmsg_entry, struct sock *sk, struct msghdr *msg)
{
	if (!sk || !msg)
		return 0;
	struct dns_recv_args args = { .sk = sk, .msg = msg };
	pnet_stash_first_iov(msg, &args.iov_base, &args.iov_len);
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&dns_active_recv, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(dns_udp_recvmsg, int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct dns_recv_args *args = bpf_map_lookup_elem(&dns_active_recv, &id);
	if (!args)
		return 0;
	struct sock *sk = args->sk;
	struct msghdr *msg = args->msg;
	__u64 iov_base = args->iov_base;
	__u64 iov_len = args->iov_len;
	bpf_map_delete_elem(&dns_active_recv, &id);

	if (ret <= 0 || !sk || !msg)
		return 0;

	struct dns_event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event));
	event->kind = PNET_EVENT_DNS;
	event->direction = PNET_DIR_RESPONSE;
	event->cgroup_id = current_cgroup_id();
	event->pid = id >> 32;
	fill_tuple(&event->tuple, sk, msg);
	if (pnet_copy_saved_payload(iov_base, iov_len, event->payload,
				    &event->payload_len, (__u32)ret,
				    PNET_DNS_PAYLOAD_BYTES) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}
