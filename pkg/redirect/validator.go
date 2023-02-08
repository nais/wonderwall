package redirect

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	mw "github.com/nais/wonderwall/pkg/middleware"
)

var (
	// Used to check final redirects are not susceptible to open redirects.
	// Matches //, /\ and both of these with whitespace in between (eg / / or / \).
	invalidRedirectRegex = regexp.MustCompile(`[/\\](?:[\s\v]*|\.{1,2})[/\\]`)
)

type Validator struct {
	allowedDomains []string
	urlType        URLType
}

type URLType int

const (
	Relative URLType = iota
	Absolute
)

func NewValidator(urlType URLType, allowedDomains []string) *Validator {
	return &Validator{urlType: urlType, allowedDomains: allowedDomains}
}

func (v *Validator) IsValidRedirect(r *http.Request, redirect string) bool {
	switch v.urlType {
	case Absolute:
		return v.isValidAbsoluteRedirect(r, redirect)
	case Relative:
		return v.isValidRelativeRedirect(r, redirect)
	default:
		return v.isValidAbsoluteRedirect(r, redirect)
	}
}

// isValidRelativeRedirect validates that the given redirect string is a valid relative URL.
// It must be an absolute path (i.e. has a leading '/').
func (v *Validator) isValidRelativeRedirect(r *http.Request, redirect string) bool {
	u, ok := parsableRequestURI(r, redirect)
	if !ok {
		return false
	}

	if isRelativeURL(u) && isValidAbsolutePath(u.String()) {
		return true
	}

	mw.LogEntryFrom(r).Infof("validator: not a valid relative URL")
	return false
}

// isValidAbsoluteRedirect validates that the given redirect string is a valid absolute URL.
// It must use the 'http' or 'https' scheme.
// It must point to a host that matches the configured list of allowed domains.
func (v *Validator) isValidAbsoluteRedirect(r *http.Request, redirect string) bool {
	u, ok := parsableRequestURI(r, redirect)
	if !ok {
		return false
	}

	if !isRelativeURL(u) && isValidScheme(u) && isAllowedHost(u, v.allowedDomains) {
		return true
	}

	if isRelativeURL(u) {
		mw.LogEntryFrom(r).Infof("validator: not an absolute URL")
		return false
	}

	if !isValidScheme(u) {
		mw.LogEntryFrom(r).Infof("validator: invalid scheme; must be one of ['http', 'https']")
		return false
	}

	if !isAllowedHost(u, v.allowedDomains) {
		mw.LogEntryFrom(r).Infof("validator: host does not match any allowlisted domains: %q", v.allowedDomains)
		return false
	}

	return false
}

func parsableRequestURI(r *http.Request, redirect string) (*url.URL, bool) {
	if redirect == "" {
		mw.LogEntryFrom(r).Infof("validator: redirect is empty")
		return nil, false
	}

	u, err := url.ParseRequestURI(redirect)
	if err != nil {
		mw.LogEntryFrom(r).Infof("validator: %+v", err)
		return nil, false
	}

	return u, true
}

func isAllowedHost(u *url.URL, allowedDomains []string) bool {
	host := u.Host
	hostname := u.Hostname()

	if host == "" || hostname == "" || len(allowedDomains) == 0 {
		return false
	}

	for _, allowed := range allowedDomains {
		if isAllowedDomain(u, allowed) {
			return true
		}
	}

	return false
}

func isValidScheme(u *url.URL) bool {
	return u.Scheme == "http" || u.Scheme == "https"
}

func isRelativeURL(u *url.URL) bool {
	return u.Scheme == "" && u.Host == ""
}

func isValidAbsolutePath(redirect string) bool {
	return strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !invalidRedirectRegex.MatchString(redirect)
}

func isAllowedDomain(u *url.URL, allowed string) bool {
	host := u.Host
	hostname := u.Hostname()

	// exact match on host:port or host
	if host == allowed || hostname == allowed {
		return true
	}

	// subdomain of allowed domain
	if !strings.HasPrefix(allowed, ".") {
		allowed = "." + allowed
	}
	return strings.HasSuffix(host, allowed)
}
