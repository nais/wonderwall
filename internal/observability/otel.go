package observability

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/uptrace/opentelemetry-go-extra/otellogrus"
	"go.opentelemetry.io/otel/attribute"
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

func SetupOpenTelemetry(ctx context.Context, attributes OtelResourceAttributes) (func(context.Context), error) {
	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	res, err := newResource(attributes.KeyValues())
	if err != nil {
		return nil, err
	}

	tracerProvider, err := newTraceProvider(ctx, res)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(tracerProvider)
	tracer = tracerProvider.Tracer(attributes.ServiceName)

	log.Infof("opentelemetry: initialized configuration")
	shutdown := func(ctx context.Context) {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			log.Fatalf("fatal: otel shutdown error: %+v", err)
		}
	}

	// Add OpenTelemetry logging hook to logrus.
	// This attaches logs to the associated span in the given log context as events.
	log.AddHook(otellogrus.NewHook(otellogrus.WithLevels(
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
	)))

	return shutdown, nil
}

type OtelResourceAttributes struct {
	ServiceName         string
	ServiceVersion      string
	IdentityProvider    string
	IdentityProviderURL string
	AutoLoginEnabled    bool
	SSOEnabled          bool
	SSOMode             string
}

func (a OtelResourceAttributes) KeyValues() []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(a.ServiceName),
		semconv.ServiceVersion(a.ServiceVersion),
		attribute.String("wonderwall.identity_provider.name", a.IdentityProvider),
		attribute.String("wonderwall.identity_provider.url", a.IdentityProviderURL),
		attribute.Bool("wonderwall.autologin", a.AutoLoginEnabled),
		attribute.Bool("wonderwall.sso", a.SSOEnabled),
	}
	if a.SSOEnabled {
		attrs = append(attrs, attribute.String("wonderwall.sso.mode", a.SSOMode))
	}
	return attrs
}

func newResource(attributes []attribute.KeyValue) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			attributes...,
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
