package http

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/nais/wonderwall/pkg/cookie"
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

// Attributes returns a map of interesting properties for the request.
func Attributes(r *http.Request) map[string]any {
	return map[string]any{
		"request.cookies":         nonEmptyRequestCookies(r),
		"request.host":            r.Host,
		"request.is_navigational": IsNavigationRequest(r),
		"request.method":          r.Method,
		"request.path":            r.URL.Path,
		"request.protocol":        r.Proto,
		"request.referer":         refererStripped(r),
		"request.sec_fetch_dest":  r.Header.Get("Sec-Fetch-Dest"),
		"request.sec_fetch_mode":  r.Header.Get("Sec-Fetch-Mode"),
		"request.sec_fetch_site":  r.Header.Get("Sec-Fetch-Site"),
		"request.user_agent":      r.UserAgent(),
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
