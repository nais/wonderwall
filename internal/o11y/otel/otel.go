package otel

import (
	"context"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	log "github.com/sirupsen/logrus"
	"github.com/uptrace/opentelemetry-go-extra/otellogrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const (
	// How long between each time OT sends something to the collector.
	batchTimeout = 5 * time.Second
)

var tracer = noop.NewTracerProvider().Tracer("noop")

func Setup(ctx context.Context, cfg *config.Config) (func(context.Context), error) {
	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	res, err := newResource(attributesFrom(cfg))
	if err != nil {
		return nil, err
	}

	tracerProvider, err := newTraceProvider(ctx, res)
	if err != nil {
		return nil, err
	}
	otel.SetTracerProvider(tracerProvider)
	tracer = tracerProvider.Tracer(cfg.OpenTelemetry.ServiceName)

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

func StartSpan(ctx context.Context, spanName string) (context.Context, trace.Span) {
	return tracer.Start(ctx, spanName)
}

// StartSpanFromRequest starts a span from an incoming HTTP request and returns th request with the updated context.
func StartSpanFromRequest(r *http.Request, spanName string) (*http.Request, trace.Span) {
	ctx := r.Context()
	ctx, span := StartSpan(ctx, spanName)
	return r.WithContext(ctx), span
}

func AddErrorEvent(span trace.Span, eventName, errType string, err error) {
	span.AddEvent(eventName, trace.WithAttributes(
		semconv.ExceptionTypeKey.String(errType),
		semconv.ExceptionMessageKey.String(err.Error()),
	))
}

func attributesFrom(cfg *config.Config) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.OpenTelemetry.ServiceName),
		semconv.ServiceVersion(cfg.Version),
		attribute.String("wonderwall.identity_provider.name", string(cfg.OpenID.Provider)),
		attribute.String("wonderwall.identity_provider.url", cfg.OpenID.WellKnownURL),
		attribute.Bool("wonderwall.autologin", cfg.AutoLogin),
		attribute.Bool("wonderwall.sso", cfg.SSO.Enabled),
	}
	if cfg.SSO.Enabled {
		attrs = append(attrs, attribute.String("wonderwall.sso.mode", string(cfg.SSO.Mode)))
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

func newTraceProvider(ctx context.Context, res *resource.Resource) (*tracesdk.TracerProvider, error) {
	traceExporter, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, err
	}

	traceProvider := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(
			traceExporter,
			tracesdk.WithBatchTimeout(batchTimeout),
		),
		tracesdk.WithResource(res),
	)
	return traceProvider, nil
}
