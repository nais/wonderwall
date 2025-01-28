package observability

import (
	"context"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace/noop"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	// How long between each time OT sends something to the collector.
	batchTimeout = 5 * time.Second
)

var tracer = noop.NewTracerProvider().Tracer("noop")

func Tracer() oteltrace.Tracer {
	return tracer
}

func OpenTelemetry(ctx context.Context, cfg *config.Config) (func(context.Context) error, error) {
	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	res, err := newResource(cfg.OpenTelemetry.ServiceName, cfg.Version)
	if err != nil {
		return nil, err
	}

	tracerProvider, err := newTraceProvider(ctx, res)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(tracerProvider)
	tracer = tracerProvider.Tracer("wonderwall")

	log.Infof("opentelemetry: initialized configuration")
	shutdown := func(ctx context.Context) error {
		return tracerProvider.Shutdown(ctx)
	}
	return shutdown, nil
}

func newResource(serviceName, serviceVersion string) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
		),
	)
}

func newPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func newTraceProvider(ctx context.Context, res *resource.Resource) (*trace.TracerProvider, error) {
	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, err
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(
			traceExporter,
			trace.WithBatchTimeout(batchTimeout),
		),
		trace.WithResource(res),
	)
	return traceProvider, nil
}
