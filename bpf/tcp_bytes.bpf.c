#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx)
{
	struct tcp_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->kind = 6;
	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tuple.family = AF_INET_VALUE;
	event->value = ctx->snd_nxt - ctx->snd_una;

	bpf_ringbuf_submit(event, 0);
	return 0;
}
