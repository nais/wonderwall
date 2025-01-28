package middleware

import (
	"context"
	"net/http"

	chi_middleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

func CorrelationIDHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(chi_middleware.RequestIDHeader)
		if len(id) == 0 {
			id = uuid.New().String()
		}

		ctx := r.Context()
		span := trace.SpanFromContext(ctx)
		if span.SpanContext().HasTraceID() {
			id = span.SpanContext().TraceID().String()
		}

		ctx = context.WithValue(ctx, chi_middleware.RequestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}
