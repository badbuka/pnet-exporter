#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * l7 captures up to PNET_L7_PAYLOAD_BYTES bytes of the first iovec
 * for each tcp_sendmsg / tcp_recvmsg call. Protocol classification
 * happens entirely in user-space (internal/protocol/) so this program
 * stays kernel-version friendly. A per-tuple timestamp map allows the
 * Go side to compute simple request/response durations.
 */

struct flow_key {
	__u32 pid_tgid_hi;
	__u32 pid_tgid_lo;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow_key);
	__type(value, __u64);
	__uint(max_entries, 65536);
} send_ts SEC(".maps");

/*
 * tcp_recvmsg has to be captured at kretprobe (the user buffer is empty
 * at entry; payload only lands in it after the kernel finishes
 * copying), so we stash sk/msg per pid_tgid on entry and consume them
 * on return.
 */
struct l7_recv_args {
	struct sock *sk;
	__u64 iov_base;
	__u64 iov_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct l7_recv_args);
	__uint(max_entries, 4096);
} l7_active_recv SEC(".maps");

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

/*
 * copy_iov_payload reads up to PNET_L7_PAYLOAD_BYTES bytes from the
 * first iovec backing `msg`. max_len caps the read to bytes the kernel
 * actually transferred (tcp_sendmsg `size` arg or tcp_recvmsg return
 * value); pass 0 to fall back to iov->iov_len.
 */
static __always_inline int copy_iov_payload(struct msghdr *msg, __u8 *dst,
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
	if (len > PNET_L7_PAYLOAD_BYTES)
		len = PNET_L7_PAYLOAD_BYTES;
	if (bpf_probe_read_user(dst, len, (const void *)(unsigned long)base) < 0)
		return -1;
	*out_len = (__u16)len;
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(l7_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct l7_event *event;
	struct flow_key key = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (!sk || !msg)
		return 0;

	key.pid_tgid_hi = pid_tgid >> 32;
	key.pid_tgid_lo = (__u32)pid_tgid;
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&send_ts, &key, &ts, BPF_ANY);

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event));
	event->kind = PNET_EVENT_L7;
	event->direction = PNET_DIR_REQUEST;
	event->cgroup_id = current_cgroup_id();
	event->pid = pid_tgid >> 32;
	event->elapsed_ns = 0;
	fill_tuple(&event->tuple, sk);
	if (copy_iov_payload(msg, event->payload, &event->payload_len,
			     (__u32)size) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(l7_tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg)
{
	if (!sk || !msg)
		return 0;
	struct l7_recv_args args = { .sk = sk };
	pnet_stash_first_iov(msg, &args.iov_base, &args.iov_len);
	__u64 id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&l7_active_recv, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(l7_tcp_recvmsg, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct l7_recv_args *args =
		bpf_map_lookup_elem(&l7_active_recv, &pid_tgid);
	if (!args)
		return 0;
	struct sock *sk = args->sk;
	__u64 iov_base = args->iov_base;
	__u64 iov_len = args->iov_len;
	bpf_map_delete_elem(&l7_active_recv, &pid_tgid);

	if (ret <= 0 || !sk)
		return 0;

	struct flow_key key = {
		.pid_tgid_hi = pid_tgid >> 32,
		.pid_tgid_lo = (__u32)pid_tgid,
	};
	__u64 *ts;
	__u64 elapsed = 0;
	ts = bpf_map_lookup_elem(&send_ts, &key);
	if (ts) {
		elapsed = bpf_ktime_get_ns() - *ts;
		bpf_map_delete_elem(&send_ts, &key);
	}

	struct l7_event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	__builtin_memset(event, 0, sizeof(*event));
	event->kind = PNET_EVENT_L7;
	event->direction = PNET_DIR_RESPONSE;
	event->cgroup_id = current_cgroup_id();
	event->pid = pid_tgid >> 32;
	event->elapsed_ns = elapsed;
	fill_tuple(&event->tuple, sk);
	if (pnet_copy_saved_payload(iov_base, iov_len, event->payload,
				    &event->payload_len, (__u32)ret,
				    PNET_L7_PAYLOAD_BYTES) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}
