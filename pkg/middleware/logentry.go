package middleware

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	httpinternal "github.com/nais/wonderwall/internal/http"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/nais/wonderwall/pkg/cookie"
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
		WithFields(requestFields(r)).
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
		requestFields: requestFields(r),
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

func requestFields(r *http.Request) log.Fields {
	fields := log.Fields{
		"request_cookies":         nonEmptyRequestCookies(r),
		"request_host":            r.Host,
		"request_is_navigational": httpinternal.IsNavigationRequest(r),
		"request_method":          r.Method,
		"request_path":            r.URL.Path,
		"request_protocol":        r.Proto,
		"request_referer":         refererStripped(r),
		"request_sec_fetch_dest":  r.Header.Get("Sec-Fetch-Dest"),
		"request_sec_fetch_mode":  r.Header.Get("Sec-Fetch-Mode"),
		"request_sec_fetch_site":  r.Header.Get("Sec-Fetch-Site"),
		"request_user_agent":      r.UserAgent(),
	}

	span := trace.SpanFromContext(r.Context())
	for k, v := range fields {
		attrKey := "wonderwall." + k
		span.SetAttributes(attribute.String(attrKey, fmt.Sprint(v)))
	}

	return fields
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

func nonEmptyRequestCookies(r *http.Request) string {
	result := make([]string, 0)

	for _, c := range r.Cookies() {
		if !isRelevantCookie(c.Name) || len(c.Value) <= 0 {
			continue
		}

		result = append(result, c.Name)
	}

	return strings.Join(result, ", ")
}

func isRelevantCookie(name string) bool {
	switch name {
	case cookie.Session,
		cookie.Login,
		cookie.Logout:
		return true
	}

	return false
}

func refererStripped(r *http.Request) string {
	referer := r.Referer()
	refererUrl, err := url.Parse(referer)
	if err == nil {
		refererUrl.RawQuery = ""
		refererUrl.RawFragment = ""
		referer = refererUrl.String()
	}

	return referer
}
