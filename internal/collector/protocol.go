package collector

import (
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

type ProtocolCollector struct {
	store *store.Store

	requests  map[store.Protocol]*prometheus.Desc
	durations map[store.Protocol]histogramDesc
}

func NewProtocolCollector(metricStore *store.Store) *ProtocolCollector {
	return &ProtocolCollector{
		store: metricStore,
		requests: map[store.Protocol]*prometheus.Desc{
			store.ProtocolHTTP: prometheus.NewDesc(
				"container_http_requests_total",
				"Total number of outbound HTTP requests made by the container.",
				appendContainerLabels("destination", "actual_destination", "status"),
				nil,
			),
			store.ProtocolPostgres: prometheus.NewDesc(
				"container_postgres_queries_total",
				"Total number of outbound Postgres queries made by the container.",
				appendContainerLabels("destination", "actual_destination", "status"),
				nil,
			),
			store.ProtocolRedis: prometheus.NewDesc(
				"container_redis_queries_total",
				"Total number of outbound Redis queries made by the container.",
				appendContainerLabels("destination", "actual_destination", "status"),
				nil,
			),
			store.ProtocolKafka: prometheus.NewDesc(
				"container_kafka_requests_total",
				"Total number of outbound Kafka requests made by the container.",
				appendContainerLabels("destination", "actual_destination", "status"),
				nil,
			),
		},
		durations: map[store.Protocol]histogramDesc{
			store.ProtocolHTTP: newHistogramDesc(
				"container_http_requests_duration_seconds",
				"Histogram of the response time for outbound HTTP requests.",
				appendContainerLabels("destination", "actual_destination"),
			),
			store.ProtocolPostgres: newHistogramDesc(
				"container_postgres_queries_duration_seconds",
				"Histogram of the response time for outbound Postgres queries.",
				appendContainerLabels("destination", "actual_destination"),
			),
			store.ProtocolRedis: newHistogramDesc(
				"container_redis_queries_duration_seconds",
				"Histogram of the response time for outbound Redis queries.",
				appendContainerLabels("destination", "actual_destination"),
			),
			store.ProtocolKafka: newHistogramDesc(
				"container_kafka_requests_duration_seconds",
				"Histogram of the response time for outbound Kafka requests.",
				appendContainerLabels("destination", "actual_destination"),
			),
		},
	}
}

func (c *ProtocolCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.requests {
		ch <- desc
	}
	for _, desc := range c.durations {
		ch <- desc.bucket
		ch <- desc.sum
		ch <- desc.count
	}
}

func (c *ProtocolCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.store.Snapshot()
	for _, series := range snapshot.Protocol {
		desc, ok := c.requests[series.Protocol]
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			desc,
			prometheus.CounterValue,
			series.Value,
			labelValues(series.Container, series.Destination, series.ActualDestination, series.Status)...,
		)
	}
	for _, series := range snapshot.ProtocolDur {
		desc, ok := c.durations[series.Protocol]
		if !ok {
			continue
		}
		collectHistogram(
			ch,
			desc,
			series.Container,
			series.Buckets,
			series.Sum,
			series.Count,
			series.Destination,
			series.ActualDestination,
		)
	}
}
