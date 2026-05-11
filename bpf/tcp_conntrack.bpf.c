#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * tcp_conntrack hooks __nf_conntrack_confirm and emits the orig/reply
 * tuple pair as a PNET_EVENT_CONNTRACK_NAT event. Userspace inverts the
 * reply tuple to derive the post-DNAT destination for outbound flows.
 *
 * The CO-RE read paths walk struct nf_conn -> tuplehash[].tuple, which
 * is the canonical layout used by netfilter. On kernels where the
 * symbol is missing the loader degrades gracefully (the .o is skipped).
 */

static __always_inline void copy_addr(__u8 *dst, struct nf_conntrack_tuple *t,
				      bool src, __u16 family)
{
	if (family == AF_INET_VALUE) {
		__be32 addr;
		if (src)
			addr = BPF_CORE_READ(t, src.u3.ip);
		else
			addr = BPF_CORE_READ(t, dst.u3.ip);
		__builtin_memcpy(dst, &addr, 4);
	} else {
		if (src)
			BPF_CORE_READ_INTO(dst, t, src.u3.in6.in6_u.u6_addr8);
		else
			BPF_CORE_READ_INTO(dst, t, dst.u3.in6.in6_u.u6_addr8);
	}
}

static __always_inline void fill_tuple(struct socket_tuple *st,
				       struct nf_conntrack_tuple *t)
{
	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, t, src.l3num);
	st->family = family;
	copy_addr(st->saddr, t, true, family);
	copy_addr(st->daddr, t, false, family);
	__be16 sport = 0, dport = 0;
	BPF_CORE_READ_INTO(&sport, t, src.u.all);
	BPF_CORE_READ_INTO(&dport, t, dst.u.all);
	st->sport = bpf_ntohs(sport);
	st->dport = bpf_ntohs(dport);
}

SEC("kprobe/__nf_conntrack_confirm")
int BPF_KPROBE(handle_conntrack_confirm, struct sk_buff *skb)
{
	struct nf_conn *ct;
	struct nat_event *event;

	ct = (struct nf_conn *)BPF_CORE_READ(skb, _nfct);
	ct = (struct nf_conn *)((unsigned long)ct & ~7UL);
	if (!ct)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	event->kind = PNET_EVENT_CONNTRACK_NAT;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;

	struct nf_conntrack_tuple *orig =
		&ct->tuplehash[0 /* IP_CT_DIR_ORIGINAL */].tuple;
	struct nf_conntrack_tuple *reply =
		&ct->tuplehash[1 /* IP_CT_DIR_REPLY */].tuple;
	fill_tuple(&event->orig, orig);
	fill_tuple(&event->reply, reply);

	bpf_ringbuf_submit(event, 0);
	return 0;
}
