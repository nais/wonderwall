package url

import (
	"net/http"
	"net/url"
)

const RedirectURLParameter = "redirect"

// CanonicalRedirectURL constructs a redirect URL that points back to the application.
func CanonicalRedirectURL(r *http.Request) string {
	redirectURL := "/"
	referer, err := url.Parse(r.Referer())
	if err == nil && len(referer.Path) > 0 {
		redirectURL = referer.Path
	}
	override := r.URL.Query().Get(RedirectURLParameter)
	if len(override) > 0 {
		referer, err = url.Parse(override)
		if err == nil {
			// strip scheme and host to avoid cross-domain redirects
			referer.Scheme = ""
			referer.Host = ""
			redirectURL = referer.String()
		}
	}
	return redirectURL
}
