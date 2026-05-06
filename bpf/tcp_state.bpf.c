#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct tcp_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tuple.family = ctx->family;
	event->tuple.sport = bpf_ntohs(ctx->sport);
	event->tuple.dport = bpf_ntohs(ctx->dport);

	if (ctx->newstate == TCP_ESTABLISHED && ctx->oldstate == TCP_SYN_SENT) {
		event->kind = PNET_EVENT_TCP_SUCCESSFUL_CONNECT;
		event->value = 1;
	} else if (ctx->oldstate == TCP_SYN_SENT && ctx->newstate == TCP_CLOSE) {
		event->kind = PNET_EVENT_TCP_FAILED_CONNECT;
		event->value = 1;
	} else if (ctx->newstate == TCP_LISTEN) {
		event->kind = PNET_EVENT_TCP_LISTEN;
		event->value = 1;
	} else {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	__builtin_memcpy(event->tuple.saddr, ctx->saddr, sizeof(ctx->saddr));
	__builtin_memcpy(event->tuple.daddr, ctx->daddr, sizeof(ctx->daddr));
	bpf_ringbuf_submit(event, 0);
	return 0;
}
