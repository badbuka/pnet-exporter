#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * trace_event_raw_tcp_event_sk_skb may be incomplete in vmlinux.h when
 * the arm64 vmlinux.h snapshot was built without the tcp tracepoint
 * definitions. The ___pnet suffix causes the BPF loader to resolve
 * actual field offsets from the running kernel's BTF at load time.
 */
struct trace_event_raw_tcp_event_sk_skb___pnet {
	unsigned long long ent[2]; /* struct trace_entry placeholder */
	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
} __attribute__((preserve_access_index));

SEC("tracepoint/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb___pnet *ctx)
{
	struct tcp_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->kind = PNET_EVENT_TCP_RETRANSMIT;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tuple.family = ctx->family;
	event->tuple.sport = bpf_ntohs(ctx->sport);
	event->tuple.dport = bpf_ntohs(ctx->dport);
	__builtin_memcpy(event->tuple.saddr, ctx->saddr, sizeof(ctx->saddr));
	__builtin_memcpy(event->tuple.daddr, ctx->daddr, sizeof(ctx->daddr));
	event->value = 1;

	bpf_ringbuf_submit(event, 0);
	return 0;
}
