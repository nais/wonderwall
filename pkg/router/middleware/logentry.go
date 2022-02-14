package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog"
	"github.com/rs/zerolog"
)

// LogEntryHandler is copied verbatim from httplog package to replace with our own requestLogger implementation.
func LogEntryHandler(logger zerolog.Logger) func(next http.Handler) http.Handler {
	var f middleware.LogFormatter = &requestLogger{logger}
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			entry := f.NewLogEntry(r)
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			buf := newLimitBuffer(512)
			ww.Tee(buf)

			t1 := time.Now()
			defer func() {
				var respBody []byte
				if ww.Status() >= 400 {
					respBody, _ = ioutil.ReadAll(buf)
				}
				entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), respBody)
			}()

			next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
		}
		return http.HandlerFunc(fn)
	}
}

func LogEntry(ctx context.Context) zerolog.Logger {
	entry := ctx.Value(middleware.LogEntryCtxKey).(*requestLoggerEntry)
	return entry.Logger
}

type requestLogger struct {
	Logger zerolog.Logger
}

func (l *requestLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	entry := &requestLoggerEntry{}
	entry.Logger = l.Logger.With().Fields(requestLogFields(r)).Logger()
	return entry
}

type requestLoggerEntry struct {
	Logger zerolog.Logger
	msg    string
}

func (l *requestLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	msg := fmt.Sprintf("response: HTTP %d (%s)", status, statusLabel(status))
	if l.msg != "" {
		msg = fmt.Sprintf("%s - %s", msg, l.msg)
	}

	responseLog := map[string]interface{}{
		"status":  status,
		"bytes":   bytes,
		"elapsed": float64(elapsed.Nanoseconds()) / 1000000.0, // in milliseconds
	}

	l.Logger.WithLevel(statusLevel(status)).Fields(map[string]interface{}{
		"httpResponse": responseLog,
	}).Msgf(msg)
}

func (l *requestLoggerEntry) Panic(v interface{}, stack []byte) {
	stacktrace := "#"
	if httplog.DefaultOptions.JSON {
		stacktrace = string(stack)
	}

	l.Logger = l.Logger.With().
		Str("stacktrace", stacktrace).
		Str("panic", fmt.Sprintf("%+v", v)).
		Logger()

	l.msg = fmt.Sprintf("%+v", v)

	if !httplog.DefaultOptions.JSON {
		middleware.PrintPrettyStack(v)
	}
}

func statusLevel(status int) zerolog.Level {
	switch {
	case status >= 400:
		return zerolog.InfoLevel
	default:
		return zerolog.DebugLevel
	}
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

func requestLogFields(r *http.Request) map[string]interface{} {
	requestFields := map[string]interface{}{
		"cookies":       requestCookies(r),
		"protocol":      r.Proto,
		"requestMethod": r.Method,
		"requestPath":   r.URL.Path,
		"userAgent":     r.UserAgent(),
	}

	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		requestFields["requestID"] = reqID
	}

	return map[string]interface{}{
		"httpRequest": requestFields,
	}
}

type requestCookie struct {
	Name    string `json:"name"`
	IsEmpty bool   `json:"isEmpty"`
}

func requestCookies(r *http.Request) []requestCookie {
	result := make([]requestCookie, 0)

	for _, c := range r.Cookies() {
		result = append(result, requestCookie{
			Name:    c.Name,
			IsEmpty: len(c.Value) <= 0,
		})
	}

	return result
}

// limitBuffer is used to pipe response body information from the
// response writer to a certain limit amount. The idea is to read
// a portion of the response body such as an error response so we
// may log it.
//
// Copied verbatim from httplog package as it is unexported.
type limitBuffer struct {
	*bytes.Buffer
	limit int
}

func newLimitBuffer(size int) io.ReadWriter {
	return limitBuffer{
		Buffer: bytes.NewBuffer(make([]byte, 0, size)),
		limit:  size,
	}
}

func (b limitBuffer) Write(p []byte) (n int, err error) {
	if b.Buffer.Len() >= b.limit {
		return len(p), nil
	}
	limit := b.limit
	if len(p) < limit {
		limit = len(p)
	}
	return b.Buffer.Write(p[:limit])
}

func (b limitBuffer) Read(p []byte) (n int, err error) {
	return b.Buffer.Read(p)
}
