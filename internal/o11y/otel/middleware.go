package otel

import (
	"context"
	"fmt"
	"net/http"

	chi_middleware "github.com/go-chi/chi/v5/middleware"
	httpinternal "github.com/nais/wonderwall/internal/http"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func Middleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		span := trace.SpanFromContext(ctx)

		attrs := httpinternal.Attributes(r)
		for k, v := range attrs {
			switch v := v.(type) {
			case bool:
				span.SetAttributes(attribute.Bool(k, v))
			default:
				span.SetAttributes(attribute.String(k, fmt.Sprint(v)))
			}
		}

		// Override request ID with trace ID if available.
		if span.SpanContext().HasTraceID() {
			id := span.SpanContext().TraceID().String()
			ctx = context.WithValue(ctx, chi_middleware.RequestIDKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			next.ServeHTTP(w, r)
		}
	}

	return http.HandlerFunc(fn)
}
