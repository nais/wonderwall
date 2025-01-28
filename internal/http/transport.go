package http

import (
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var (
	defaultTransport *http.Transport
	once             sync.Once
)

func Transport() http.RoundTripper {
	once.Do(func() {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 200
		t.MaxIdleConnsPerHost = 100
		t.IdleConnTimeout = 5 * time.Second

		defaultTransport = t
	})

	return otelhttp.NewTransport(defaultTransport)
}
