#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * outbound_socks remembers sockets that transitioned through
 * TCP_SYN_SENT to TCP_ESTABLISHED (i.e. outbound connections we know
 * we initiated). On the matching ESTABLISHED->CLOSE transition we emit
 * a close event so userspace can decrement the active-connections gauge
 * without double-counting inbound sockets.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 65536);
} outbound_socks SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct tcp_event *event;
	__u64 sk = (__u64)ctx->skaddr;
	__u8 known_outbound = 0;

	if (ctx->oldstate == TCP_ESTABLISHED && ctx->newstate == TCP_CLOSE) {
		if (bpf_map_lookup_elem(&outbound_socks, &sk)) {
			known_outbound = 1;
			bpf_map_delete_elem(&outbound_socks, &sk);
		} else {
			return 0;
		}
	}

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
		__u8 one = 1;
		bpf_map_update_elem(&outbound_socks, &sk, &one, BPF_ANY);
	} else if (ctx->oldstate == TCP_SYN_SENT && ctx->newstate == TCP_CLOSE) {
		event->kind = PNET_EVENT_TCP_FAILED_CONNECT;
		event->value = 1;
	} else if (ctx->newstate == TCP_LISTEN) {
		event->kind = PNET_EVENT_TCP_LISTEN;
		event->value = 1;
	} else if (known_outbound) {
		event->kind = PNET_EVENT_TCP_CLOSE;
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
