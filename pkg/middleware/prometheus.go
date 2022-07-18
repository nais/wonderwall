// This code was originally written by Rene Zbinden and modified by Vladimir Konovalov.
// Copied from https://github.com/766b/chi-prometheus and further adapted.

package middleware

import (
	"net/http"
	"strconv"
	"time"

	chi_middleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	defaultBuckets = []float64{.001, .01, .05, .1, .5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5}
)

const (
	reqsName    = "requests_total"
	latencyName = "request_duration_seconds"
)

// PrometheusMiddleware is a handler that exposes prometheus metrics for the number of requests,
// the latency and the response size, partitioned by status code, method and HTTP path.
type PrometheusMiddleware struct {
	reqs    *prometheus.CounterVec
	latency *prometheus.HistogramVec
}

// NewPrometheusMiddleware returns a new PrometheusMiddleware handler.
func NewPrometheusMiddleware(name, provider string, buckets ...float64) *PrometheusMiddleware {
	var m PrometheusMiddleware
	m.reqs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        reqsName,
			Help:        "How many HTTP requests processed, partitioned by status code, method and HTTP path.",
			ConstLabels: prometheus.Labels{"service": name, "provider": provider},
		},
		[]string{"code", "method", "path", "host"},
	)

	if len(buckets) == 0 {
		buckets = defaultBuckets
	}
	m.latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        latencyName,
		Help:        "How long it took to process the request, partitioned by status code, method and HTTP path.",
		ConstLabels: prometheus.Labels{"service": name, "provider": provider},
		Buckets:     buckets,
	},
		[]string{"code", "method", "path", "host"},
	)

	prometheus.Register(m.reqs)
	prometheus.Register(m.latency)

	return &m
}

func (m *PrometheusMiddleware) Initialize(path, method string, code int) {
	m.reqs.WithLabelValues(
		strconv.Itoa(code),
		method,
		path,
	)
}

func (m *PrometheusMiddleware) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chi_middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		statusCode := strconv.Itoa(ww.Status())
		duration := time.Since(start)
		m.reqs.WithLabelValues(statusCode, r.Method, r.URL.Path, r.Host).Inc()
		m.latency.WithLabelValues(statusCode, r.Method, r.URL.Path, r.Host).Observe(duration.Seconds())
	}
	return http.HandlerFunc(fn)
}
