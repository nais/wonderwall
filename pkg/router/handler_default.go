package router

import (
	"context"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// Default proxies all requests upstream
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Duplicate the incoming request, and delete any authentication.
	upstreamRequest := r.Clone(ctx)
	upstreamRequest.Header.Del("authorization")
	upstreamRequest.Header.Del("x-pwned-by")

	sess, err := h.getSessionFromCookie(r)
	if err == nil && sess != nil && len(sess.AccessToken) > 0 {
		// add authentication if session cookie and token checks out
		upstreamRequest.Header.Add("authorization", "Bearer "+sess.AccessToken)
		upstreamRequest.Header.Add("x-pwned-by", "wonderwall") // todo: request id for tracing
	}

	// Request should go to correct host
	upstreamRequest.Host = r.Host
	upstreamRequest.URL.Host = h.UpstreamHost
	upstreamRequest.URL.Scheme = "http"
	upstreamRequest.RequestURI = ""
	// Attach request body from original request
	upstreamRequest.Body = r.Body
	defer upstreamRequest.Body.Close()

	// Make sure requests aren't silently redirected
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	upstreamResponse, err := client.Do(upstreamRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(err.Error()))
		return
	}

	for key, values := range upstreamResponse.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(upstreamResponse.StatusCode)

	// Forward server's reply downstream
	_, err = io.Copy(w, upstreamResponse.Body)
	if err != nil {
		log.Errorf("proxy data from upstream to client: %s", err)
	}
}
