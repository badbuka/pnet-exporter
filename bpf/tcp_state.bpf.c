#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * outbound_socks remembers sockets that transitioned through
 * TCP_SYN_SENT to TCP_ESTABLISHED (i.e. outbound connections we know
 * we initiated). On ANY transition into TCP_CLOSE of such a socket we
 * emit a close event so userspace can decrement the active-connections
 * gauge without double-counting inbound sockets. Note the close
 * transition usually comes from FIN_WAIT2/CLOSING/LAST_ACK
 * (tcp_time_wait -> tcp_done); ESTABLISHED->CLOSE only fires on
 * RST/abort paths, so keying on the old state would miss every
 * graceful close.
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

	if (ctx->newstate == TCP_CLOSE && ctx->oldstate != TCP_SYN_SENT) {
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
	__builtin_memset(event, 0, sizeof(*event));

	event->cgroup_id = current_cgroup_id();
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->tuple.family = ctx->family;
	/* The tracepoint stores sport/dport in host byte order (since
	 * kernel 4.19); applying ntohs again would byte-swap them. */
	event->tuple.sport = ctx->sport;
	event->tuple.dport = ctx->dport;

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

	if (ctx->family == AF_INET6_VALUE) {
		__builtin_memcpy(event->tuple.saddr, ctx->saddr_v6, sizeof(ctx->saddr_v6));
		__builtin_memcpy(event->tuple.daddr, ctx->daddr_v6, sizeof(ctx->daddr_v6));
	} else {
		__builtin_memcpy(event->tuple.saddr, ctx->saddr, sizeof(ctx->saddr));
		__builtin_memcpy(event->tuple.daddr, ctx->daddr, sizeof(ctx->daddr));
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}
