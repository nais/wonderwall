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
//
// This depends on the presence of the Fetch metadata headers, mostly present in modern browsers.
// For compatibility with older browsers, requests without these headers are still allowed to pass through.
func DisallowNonNavigationalRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if HasSecFetchMetadata(r) && !IsNavigationRequest(r) {
			span := trace.SpanFromContext(r.Context())
			span.SetAttributes(attribute.Bool("request.disallowed", true))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthenticated", "error_description": "this is an interactive endpoint; user-agents must be navigated to this endpoint", "error_path": "` + r.URL.Path + `"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
