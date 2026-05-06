# Metrics

All metrics include `node_hostname`. Container-scoped metrics also include `container_id`, `container_name`, and `pod_id` labels. Destination and protocol label values are bounded by exporter configuration; overflow values are reported as `~other`.

## Network

- `container_net_tcp_listen_info` gauge: labels `listen_addr`, `proxy`.
- `container_net_tcp_successful_connects_total` counter: labels `destination`, `actual_destination`.
- `container_net_tcp_failed_connects_total` counter: label `destination`.
- `container_net_tcp_retransmits_total` counter: labels `destination`, `actual_destination`.
- `container_net_tcp_active_connections` gauge: labels `destination`, `actual_destination`.
- `container_net_tcp_bytes_sent_total` counter: labels `destination`, `actual_destination`.
- `container_net_tcp_bytes_received_total` counter: labels `destination`, `actual_destination`.
- `container_net_latency_seconds` gauge: label `destination_ip`.
- `ip_to_fqdn` gauge: labels `ip`, `fqdn`.

## DNS

- `container_dns_requests_total` counter: labels `domain`, `request_type`, `status`.
- `container_dns_requests_duration_seconds_bucket` counter: labels `le`.
- `container_dns_requests_duration_seconds_sum` counter.
- `container_dns_requests_duration_seconds_count` counter.

The originally requested DNS duration metric maps to the standard Prometheus histogram family above.

## HTTP

- `container_http_requests_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_http_requests_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_http_requests_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_http_requests_duration_seconds_count` counter: labels `destination`, `actual_destination`.

## Postgres

- `container_postgres_queries_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_postgres_queries_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_postgres_queries_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_postgres_queries_duration_seconds_count` counter: labels `destination`, `actual_destination`.

## Redis

- `container_redis_queries_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_redis_queries_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_redis_queries_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_redis_queries_duration_seconds_count` counter: labels `destination`, `actual_destination`.

## Kafka

- `container_kafka_requests_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_kafka_requests_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_kafka_requests_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_kafka_requests_duration_seconds_count` counter: labels `destination`, `actual_destination`.
