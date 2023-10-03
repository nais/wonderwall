package ingress

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/nais/wonderwall/pkg/config"
)

const (
	XForwardedHost = "X-Forwarded-Host"
)

type Ingresses struct {
	ingressMap map[string]Ingress
	hosts      []string
	paths      []string
	urls       []string
}

func ParseIngresses(cfg *config.Config) (*Ingresses, error) {
	ingresses := cfg.Ingresses
	if len(ingresses) == 0 {
		return nil, fmt.Errorf("must have at least 1 ingress")
	}

	seen := make(map[string]Ingress)

	for _, raw := range ingresses {
		ingress, err := ParseIngress(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing ingress '%s': %w", raw, err)
		}

		if _, found := seen[ingress.String()]; !found {
			seen[ingress.String()] = *ingress
		}
	}

	return &Ingresses{
		ingressMap: seen,
		hosts:      mapIngresses(seen, Ingress.Host),
		paths:      mapIngresses(seen, Ingress.Path),
		urls:       mapIngresses(seen, Ingress.String),
	}, nil
}

func (i *Ingresses) Hosts() []string {
	return i.hosts
}

func (i *Ingresses) Paths() []string {
	return i.paths
}

func (i *Ingresses) Strings() []string {
	return i.urls
}

func (i *Ingresses) MatchingIngress(r *http.Request) (Ingress, bool) {
	for _, ingress := range i.ingressMap {
		hostMatch := ingress.Host() == r.Host || ingress.Host() == r.Header.Get(XForwardedHost)
		pathMatch := ingress.Path() == i.MatchingPath(r)

		if hostMatch && pathMatch {
			return ingress, true
		}
	}

	return Ingress{}, false
}

func (i *Ingresses) MatchingPath(r *http.Request) string {
	reqPath := r.URL.Path
	result := ""

	for _, p := range i.Paths() {
		if len(p) == 0 {
			continue
		}

		if strings.HasPrefix(reqPath, p) && len(p) > len(result) {
			result = p
		}
	}

	return result
}

func (i *Ingresses) Single() Ingress {
	var res Ingress

	for _, v := range i.ingressMap {
		res = v
		break
	}

	return res
}

func mapIngresses(ingresses map[string]Ingress, fn func(i Ingress) string) []string {
	seen := make(map[string]bool, 0)
	result := make([]string, 0)

	for _, ingress := range ingresses {
		value := fn(ingress)

		if _, found := seen[value]; !found {
			seen[value] = true
			result = append(result, value)
		}
	}

	return result
}

func ParseIngress(ingress string) (*Ingress, error) {
	if len(ingress) == 0 {
		return nil, fmt.Errorf("ingress cannot be empty")
	}

	u, err := url.ParseRequestURI(ingress)
	if err != nil {
		return nil, err
	}

	if len(u.Host) == 0 {
		return nil, fmt.Errorf("must have non-empty host")
	}

	err = mustScheme(u)
	if err != nil {
		return nil, err
	}

	u.Path = strings.TrimRight(u.Path, "/")

	return &Ingress{
		URL: u,
	}, nil
}

func mustScheme(u *url.URL) error {
	validSchemes := []string{"http", "https"}

	valid := false
	for _, scheme := range validSchemes {
		if u.Scheme == scheme {
			valid = true
		}
	}

	if !valid {
		return fmt.Errorf("invalid URL scheme, must be one of %s", validSchemes)
	}

	return nil
}

type Ingress struct {
	*url.URL
}

func (i Ingress) Path() string {
	return i.URL.Path
}

func (i Ingress) Host() string {
	return i.URL.Host
}

func (i Ingress) String() string {
	return i.URL.String()
}

func (i Ingress) NewURL() *url.URL {
	u := *i.URL
	return &u
}
