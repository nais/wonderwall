package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	Namespace = "wonderwall"

	RedisOperationLabel = "operation"
)

var (
	RedisLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "redis_latency",
		Namespace: Namespace,
		Help:      "latency in redis operations",
		Buckets:   prometheus.ExponentialBuckets(0.02, 2, 14),
	}, []string{RedisOperationLabel})
)

func Handle(address string) error {
	Register(prometheus.DefaultRegisterer)
	handler := promhttp.Handler()
	return http.ListenAndServe(address, handler)
}

func Register(registry prometheus.Registerer) {
	registry.MustRegister(
		RedisLatency,
	)
}

func ObserveRedisLatency(operation string, fun func() error) error {
	timer := time.Now()
	err := fun()
	used := time.Now().Sub(timer)
	RedisLatency.With(prometheus.Labels{
		RedisOperationLabel: operation,
	}).Observe(used.Seconds())
	return err
}
