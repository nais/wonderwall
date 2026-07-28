package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/metrics"
)

func TestRegisterCollector(t *testing.T) {
	newCounter := func() *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wonderwall_test_register_collector_total",
			Help: "counter used to assert registration behaviour",
		}, []string{"label"})
	}

	first := newCounter()
	assert.Same(t, first, metrics.RegisterCollector(first), "the first registration is used as-is")

	// an equal collector is already registered, so observations on the second one would
	// never be scraped; the registered one must be returned instead
	second := newCounter()
	assert.Same(t, first, metrics.RegisterCollector(second))
	assert.NotSame(t, second, metrics.RegisterCollector(second))
}
