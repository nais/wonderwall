package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/nais/wonderwall/pkg/config"
)

const (
	Namespace = "wonderwall"

	LabelHpa       = "hpa"
	LabelOperation = "operation"
	LabelProvider  = "provider"
)

type Hpa = string

const (
	HpaRate = "rate"
)

type LogoutOperation = string

const (
	LogoutOperationFrontChannel  = "front_channel"
	LogoutOperationLocal         = "local"
	LogoutOperationSelfInitiated = "self_initiated"
)

type RedisOperation = string

const (
	RedisOperationRead   = "Read"
	RedisOperationWrite  = "Write"
	RedisOperationUpdate = "Update"
	RedisOperationDelete = "Delete"
)

var (
	RedisLatency = redisLatency()
	Logins       = logins()
	Logouts      = logouts()
)

func redisLatency(constLabels ...prometheus.Labels) *prometheus.HistogramVec {
	opts := prometheus.HistogramOpts{
		Name:      "redis_latency",
		Namespace: Namespace,
		Help:      "latency in redis operations, in seconds",
		Buckets:   prometheus.ExponentialBuckets(0.001, 2, 16),
	}

	if len(constLabels) > 0 {
		opts.ConstLabels = constLabels[0]
	}

	return prometheus.NewHistogramVec(opts, []string{LabelOperation})
}

func logins(constLabels ...prometheus.Labels) prometheus.Counter {
	opts := prometheus.CounterOpts{
		Name:      "logins",
		Namespace: Namespace,
		Help:      "cumulative number of successful logins",
		ConstLabels: prometheus.Labels{
			LabelHpa: HpaRate,
		},
	}

	if len(constLabels) > 0 {
		opts.ConstLabels = constLabels[0]
	}

	return prometheus.NewCounter(opts)
}

func logouts(constLabels ...prometheus.Labels) *prometheus.CounterVec {
	opts := prometheus.CounterOpts{
		Name:      "logouts",
		Namespace: Namespace,
		Help:      "cumulative number of successful logouts",
		ConstLabels: prometheus.Labels{
			LabelHpa: HpaRate,
		},
	}

	if len(constLabels) > 0 {
		opts.ConstLabels = constLabels[0]
	}

	return prometheus.NewCounterVec(opts, []string{LabelOperation})
}

func WithProvider(provider string) {
	RedisLatency = redisLatency(prometheus.Labels{
		LabelProvider: provider,
	})

	Logins = logins(prometheus.Labels{
		LabelHpa:      HpaRate,
		LabelProvider: provider,
	})

	Logouts = logouts(prometheus.Labels{
		LabelHpa:      HpaRate,
		LabelProvider: provider,
	})
}

// InitLabels zeroes out all possible label combinations
func InitLabels() {
	logoutOperations := []LogoutOperation{LogoutOperationSelfInitiated, LogoutOperationFrontChannel}

	for _, operation := range logoutOperations {
		Logouts.With(prometheus.Labels{LabelOperation: operation})
	}
}

func Handle(address string, provider config.Provider) error {
	WithProvider(string(provider))
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
	used := time.Since(timer)
	RedisLatency.With(prometheus.Labels{
		LabelOperation: operation,
	}).Observe(used.Seconds())
	return err
}

func ObserveLogin() {
	Logins.Inc()
}

func ObserveLogout(operation LogoutOperation) {
	Logouts.With(prometheus.Labels{
		LabelOperation: operation,
	}).Inc()
}
