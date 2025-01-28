package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"

	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/pkg/router/paths"
)

type logger struct {
	Logger   *log.Logger
	Provider string
}

// Logger provides a middleware that logs requests and responses.
func Logger(provider string) logger {
	return logger{
		Logger:   log.StandardLogger(),
		Provider: provider,
	}
}

// LogEntryFrom returns a log entry from the request context.
func LogEntryFrom(r *http.Request) *log.Entry {
	ctx := r.Context()
	entry, ok := ctx.Value(middleware.LogEntryCtxKey).(*logEntryAdapter)
	if ok {
		return entry.Logger
	}

	return log.NewEntry(log.StandardLogger()).
		WithFields(httpinternal.Attributes(r)).
		WithFields(traceFields(r))
}

func (l *logger) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		entry := l.newLogEntry(r)
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		if !strings.HasSuffix(r.URL.Path, paths.Ping) {
			t1 := time.Now()
			defer func() {
				entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), nil)
			}()
		}

		next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
	}
	return http.HandlerFunc(fn)
}

func (l *logger) newLogEntry(r *http.Request) *logEntryAdapter {
	return &logEntryAdapter{
		requestFields: httpinternal.Attributes(r),
		Logger: l.Logger.WithContext(r.Context()).
			WithField("provider", l.Provider).
			WithFields(traceFields(r)),
	}
}

// logEntryAdapter implements [middleware.LogEntry]
type logEntryAdapter struct {
	Logger        *log.Entry
	requestFields log.Fields
}

func (l *logEntryAdapter) Write(status, bytes int, _ http.Header, elapsed time.Duration, _ any) {
	responseFields := log.Fields{
		"response_status":     status,
		"response_bytes":      bytes,
		"response_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0, // in milliseconds, with fractional
	}

	l.Logger.WithFields(l.requestFields).
		WithFields(responseFields).
		Debugf("response: %d %s", status, http.StatusText(status))
}

func (l *logEntryAdapter) Panic(v interface{}, _ []byte) {
	stacktrace := "#"

	fields := log.Fields{
		"stacktrace": stacktrace,
		"error":      fmt.Sprintf("%+v", v),
	}

	l.Logger = l.Logger.WithFields(fields)
}

func traceFields(r *http.Request) log.Fields {
	fields := log.Fields{}
	span := trace.SpanFromContext(r.Context())
	if span.SpanContext().HasTraceID() {
		fields["trace_id"] = span.SpanContext().TraceID().String()
	} else {
		fields["correlation_id"] = middleware.GetReqID(r.Context())
	}

	return fields
}
