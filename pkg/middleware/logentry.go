package middleware

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/router/paths"
)

var logger *requestLogger

type LogEntryMiddleware struct{}

// LogEntry is copied verbatim from httplog package to replace with our own requestLogger implementation.
func LogEntry(provider string) LogEntryMiddleware {
	logger = &requestLogger{Logger: log.StandardLogger(), Provider: provider}
	return LogEntryMiddleware{}
}

func (l *LogEntryMiddleware) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		entry := logger.NewLogEntry(r)
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		if !strings.HasSuffix(r.URL.Path, paths.Ping) {
			entry.Logger.Debugf("request start: %s - %s", r.Method, r.URL.Path)
			t1 := time.Now()
			defer func() {
				entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), nil)
			}()
		}

		next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
	}
	return http.HandlerFunc(fn)
}

func LogEntryFrom(r *http.Request) *log.Entry {
	ctx := r.Context()
	val := ctx.Value(middleware.LogEntryCtxKey)
	entry, ok := val.(*requestLoggerEntry)
	if ok {
		return entry.Logger
	}

	entry = logger.NewLogEntry(r)
	return entry.Logger
}

type requestLogger struct {
	Logger   *log.Logger
	Provider string
}

func (l *requestLogger) NewLogEntry(r *http.Request) *requestLoggerEntry {
	referer := r.Referer()
	refererUrl, err := url.Parse(referer)
	if err == nil {
		refererUrl.RawQuery = ""
		refererUrl.RawFragment = ""
		referer = refererUrl.String()
	}

	entry := &requestLoggerEntry{}
	correlationID := middleware.GetReqID(r.Context())

	fields := log.Fields{
		"correlation_id":     correlationID,
		"provider":           l.Provider,
		"request_cookies":    nonEmptyRequestCookies(r),
		"request_host":       r.Host,
		"request_method":     r.Method,
		"request_path":       r.URL.Path,
		"request_protocol":   r.Proto,
		"request_referer":    referer,
		"request_user_agent": r.UserAgent(),
	}

	entry.Logger = l.Logger.WithFields(fields)
	return entry
}

type requestLoggerEntry struct {
	Logger *log.Entry
}

func (l *requestLoggerEntry) Write(status, bytes int, _ http.Header, elapsed time.Duration, _ any) {
	msg := fmt.Sprintf("request end: HTTP %d (%s)", status, statusLabel(status))
	fields := log.Fields{
		"response_status":     status,
		"response_bytes":      bytes,
		"response_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0, // in milliseconds, with fractional
	}

	entry := l.Logger.WithFields(fields)
	entry.Debugf(msg)
}

func (l *requestLoggerEntry) Panic(v interface{}, _ []byte) {
	stacktrace := "#"

	fields := log.Fields{
		"stacktrace": stacktrace,
		"error":      fmt.Sprintf("%+v", v),
	}

	l.Logger = l.Logger.WithFields(fields)
}

func statusLabel(status int) string {
	switch {
	case status >= 100 && status < 300:
		return "OK"
	case status >= 300 && status < 400:
		return "Redirect"
	case status >= 400 && status < 500:
		return "Client Error"
	case status >= 500:
		return "Server Error"
	default:
		return "Unknown"
	}
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
