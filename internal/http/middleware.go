package http

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// DisallowNonNavigationalRequests checks if the request is non-navigational, and if so, responds with a 401.
// We do this to separate between redirects for browser navigation and redirects for resource requests.
//
// This should only be used for endpoints that are only supposed to be _navigated to_ from a browser.
// The 401 response prevents redirecting non-navigation requests to the identity provider, which usually results in
// a CORS error for typical Fetch or XHR requests from the browser.
func DisallowNonNavigationalRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsNavigationRequest(r) {
			span := trace.SpanFromContext(r.Context())
			span.SetAttributes(attribute.Bool("request.disallowed", true))

			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error": "unauthenticated", "error_description": "this is an interactive endpoint; user-agents must be navigated to this endpoint", "error_path": "` + r.URL.Path + `"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
