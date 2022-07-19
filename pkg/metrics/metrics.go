package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	Namespace = "wonderwall"

	LabelOperation = "operation"
	LabelHpa       = "hpa"
)

type Hpa = string

const (
	HpaRate = "rate"
)

type LogoutOperation = string

const (
	LogoutOperationSelfInitiated = "self_initiated"
	LogoutOperationFrontChannel  = "front_channel"
)

type RedisOperation = string

const (
	RedisOperationRead   = "Read"
	RedisOperationWrite  = "Write"
	RedisOperationDelete = "Delete"
)

var (
	RedisLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:      "redis_latency",
		Namespace: Namespace,
		Help:      "latency in redis operations",
		Buckets:   prometheus.ExponentialBuckets(0.02, 2, 14),
	}, []string{LabelOperation})

	Logins = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "logins",
			Namespace: Namespace,
			Help:      "cumulative number of successful logins",
		},
		[]string{
			LabelHpa,
		},
	)

	Logouts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "logouts",
			Namespace: Namespace,
			Help:      "cumulative number of successful logouts",
		},
		[]string{
			LabelOperation,
			LabelHpa,
		},
	)
)

// InitLabels zeroes out all possible label combinations
func InitLabels() {
	logoutOperations := []LogoutOperation{LogoutOperationSelfInitiated, LogoutOperationFrontChannel}

	for _, operation := range logoutOperations {
		Logouts.With(prometheus.Labels{
			LabelOperation: operation,
			LabelHpa:       HpaRate,
		})
	}

	Logins.With(prometheus.Labels{
		LabelHpa: HpaRate,
	})
}

func Handle(address string) error {
	Register(prometheus.DefaultRegisterer)
	InitLabels()
	handler := promhttp.Handler()
	return http.ListenAndServe(address, handler)
}

func Register(registry prometheus.Registerer) {
	registry.MustRegister(
		RedisLatency,
		Logins,
		Logouts,
	)
}

func ObserveRedisLatency(operation string, fun func() error) error {
	timer := time.Now()
	err := fun()
	used := time.Now().Sub(timer)
	RedisLatency.With(prometheus.Labels{
		LabelOperation: operation,
	}).Observe(used.Seconds())
	return err
}

func ObserveLogin() {
	Logins.With(prometheus.Labels{
		LabelHpa: HpaRate,
	}).Inc()
}

func ObserveLogout(operation LogoutOperation) {
	Logouts.With(prometheus.Labels{
		LabelOperation: operation,
		LabelHpa:       HpaRate,
	}).Inc()
}
