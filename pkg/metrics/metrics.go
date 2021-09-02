package metrics

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

func Handle(address string) error {
	handler := promhttp.Handler()
	return http.ListenAndServe(address, handler)
}
