#ifndef PNET_EXPORTER_EVENTS_H
#define PNET_EXPORTER_EVENTS_H

/*
 * Event kind constants shared between BPF programs and Go user-space.
 *
 * The Go side mirrors these in internal/ebpf/events.go. They MUST stay in
 * sync; gaps in the numbering are reserved for future events.
 */

#define PNET_EVENT_TCP_LISTEN              1
#define PNET_EVENT_TCP_SUCCESSFUL_CONNECT  2
#define PNET_EVENT_TCP_FAILED_CONNECT      3
#define PNET_EVENT_TCP_ACTIVE_CONNECTIONS  4 /* reserved: userspace aggregates */
#define PNET_EVENT_TCP_RETRANSMIT          5
#define PNET_EVENT_TCP_BYTES_SENT          6
#define PNET_EVENT_TCP_BYTES_RECEIVED      7
#define PNET_EVENT_PROTOCOL                8 /* reserved: legacy */
#define PNET_EVENT_DNS                     9
#define PNET_EVENT_TCP_CLOSE              10
#define PNET_EVENT_CONNTRACK_NAT          11
#define PNET_EVENT_L7                     12
#define PNET_EVENT_OOM                    13
#define PNET_EVENT_TCP_INBOUND_ACCEPT     14
#define PNET_EVENT_TCP_INBOUND_CLOSE      15
#define PNET_EVENT_TCP_INBOUND_BYTES_SENT 16
#define PNET_EVENT_TCP_INBOUND_BYTES_RECEIVED 17

#define PNET_DIR_REQUEST                   0
#define PNET_DIR_RESPONSE                  1

#define PNET_L7_PAYLOAD_BYTES            256
#define PNET_DNS_PAYLOAD_BYTES           512

#endif
