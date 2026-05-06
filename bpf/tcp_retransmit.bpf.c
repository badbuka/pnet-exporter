#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	struct tcp_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->kind = 5;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tuple.family = ctx->family;
	event->tuple.sport = ctx->sport;
	event->tuple.dport = ctx->dport;
	__builtin_memcpy(event->tuple.saddr, ctx->saddr, sizeof(ctx->saddr));
	__builtin_memcpy(event->tuple.daddr, ctx->daddr, sizeof(ctx->daddr));
	event->value = 1;

	bpf_ringbuf_submit(event, 0);
	return 0;
}
