// This code was originally written by Rene Zbinden and modified by Vladimir Konovalov.
// Copied from https://github.com/766b/chi-prometheus and further adapted.

package prometheus

import (
	"net/http"
	"strconv"
	"time"

	chi_middleware "github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	defaultBuckets = []float64{.001, .01, .05, .1, .5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5}
)

const (
	reqsName    = "requests_total"
	latencyName = "request_duration_seconds"
)

type middleware func(http.Handler) http.Handler

// Middleware is a handler that exposes prometheus metrics for the number of requests,
// the latency and the response size, partitioned by status code, method and HTTP path.
type Middleware struct {
	reqs    *prometheus.CounterVec
	latency *prometheus.HistogramVec
}

// NewMiddleware returns a new prometheus Middleware handler.
func NewMiddleware(name string, buckets ...float64) *Middleware {
	var m Middleware
	m.reqs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:        reqsName,
			Help:        "How many HTTP requests processed, partitioned by status code, method and HTTP path.",
			ConstLabels: prometheus.Labels{"service": name},
		},
		[]string{"code", "method", "path"},
	)

	if len(buckets) == 0 {
		buckets = defaultBuckets
	}
	m.latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        latencyName,
		Help:        "How long it took to process the request, partitioned by status code, method and HTTP path.",
		ConstLabels: prometheus.Labels{"service": name},
		Buckets:     buckets,
	},
		[]string{"code", "method", "path"},
	)

	prometheus.Register(m.reqs)
	prometheus.Register(m.latency)

	return &m
}

func (m *Middleware) Initialize(path, method string, code int) {
	m.reqs.WithLabelValues(
		strconv.Itoa(code),
		method,
		path,
	)
}

func (m *Middleware) Handler() middleware {
	return m.handler
}

func (m Middleware) handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chi_middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		statusCode := strconv.Itoa(ww.Status())
		duration := time.Since(start)
		m.reqs.WithLabelValues(statusCode, r.Method, r.URL.Path).Inc()
		m.latency.WithLabelValues(statusCode, r.Method, r.URL.Path).Observe(duration.Seconds())
	}
	return http.HandlerFunc(fn)
}
