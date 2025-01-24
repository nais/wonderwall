package http

import (
	"net/http"
	"strings"
)

func IsNavigationRequest(r *http.Request) bool {
	// we assume that navigation requests are always GET requests
	if r.Method != http.MethodGet {
		return false
	}

	// check for top-level navigation requests
	mode := r.Header.Get("Sec-Fetch-Mode")
	dest := r.Header.Get("Sec-Fetch-Dest")
	if mode != "" && dest != "" {
		return mode == "navigate" && dest == "document"
	}

	// fallback if browser doesn't support fetch metadata
	return Accepts(r, "text/html")
}

func Accepts(r *http.Request, accepted ...string) bool {
	// iterate over all Accept headers
	for _, header := range r.Header.Values("Accept") {
		// iterate over all comma-separated values in a single Accept header
		for _, v := range strings.Split(header, ",") {
			v = strings.ToLower(v)
			v = strings.TrimSpace(v)
			v = strings.Split(v, ";")[0]

			for _, accept := range accepted {
				if v == accept {
					return true
				}
			}
		}
	}

	return false
}
