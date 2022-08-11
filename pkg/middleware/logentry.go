package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
)

var logger *requestLogger

// LogEntryHandler is copied verbatim from httplog package to replace with our own requestLogger implementation.
func LogEntryHandler(provider string) func(next http.Handler) http.Handler {
	logger = &requestLogger{Logger: log.StandardLogger(), Provider: provider}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			entry := logger.NewLogEntry(r)
			entry.WithRequestLogFields(r).Infof("%s - %s", r.Method, r.URL.Path)

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			t1 := time.Now()
			defer func() {
				entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), nil)
			}()

			next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
		}
		return http.HandlerFunc(fn)
	}
}

func LogEntry(r *http.Request) *log.Entry {
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
	entry := &requestLoggerEntry{}
	correlationID := middleware.GetReqID(r.Context())

	fields := log.Fields{
		"correlation_id": correlationID,
		"provider":       l.Provider,
	}

	entry.Logger = l.Logger.WithFields(fields)
	return entry
}

type requestLoggerEntry struct {
	Logger *log.Entry
}

func (l *requestLoggerEntry) WithRequestLogFields(r *http.Request) *log.Entry {
	fields := log.Fields{
		"request_cookies":    nonEmptyRequestCookies(r),
		"request_host":       r.Host,
		"request_method":     r.Method,
		"request_path":       r.URL.Path,
		"request_protocol":   r.Proto,
		"request_referer":    r.Referer(),
		"request_user_agent": r.UserAgent(),
	}

	return l.Logger.WithFields(fields)
}

func (l *requestLoggerEntry) Write(status, bytes int, _ http.Header, elapsed time.Duration, _ any) {
	msg := fmt.Sprintf("response: HTTP %d (%s)", status, statusLabel(status))
	fields := log.Fields{
		"response_status":     status,
		"response_bytes":      bytes,
		"response_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0, // in milliseconds, with fractional
	}

	entry := l.Logger.WithFields(fields)

	switch {
	case status >= 400:
		entry.Infof(msg)
	default:
		entry.Debugf(msg)
	}
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
		cookie.LoginLegacy:
		return true
	}

	return false
}
