package ingress_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
)

type ingressWant struct {
	path      string
	domain    string
	urlString string
}

func TestParseIngress(t *testing.T) {
	for _, test := range []struct {
		ingress string
		want    ingressWant
	}{
		{
			ingress: "https://tjenester.nav.no/sykepenger/",
			want: ingressWant{
				path:      "/sykepenger",
				domain:    "tjenester.nav.no",
				urlString: "https://tjenester.nav.no/sykepenger",
			},
		},
		{
			ingress: "https://tjenester.nav.no/sykepenger/test",
			want: ingressWant{
				path:      "/sykepenger/test",
				domain:    "tjenester.nav.no",
				urlString: "https://tjenester.nav.no/sykepenger/test",
			},
		},
		{
			ingress: "https://tjenester.nav.no/test/sykepenger/",
			want: ingressWant{
				path:      "/test/sykepenger",
				domain:    "tjenester.nav.no",
				urlString: "https://tjenester.nav.no/test/sykepenger",
			},
		},
		{
			ingress: "https://sykepenger.nav.no/",
			want: ingressWant{
				path:      "",
				domain:    "sykepenger.nav.no",
				urlString: "https://sykepenger.nav.no",
			},
		},
		{
			ingress: "https://sykepenger-test.nav.no",
			want: ingressWant{
				path:      "",
				domain:    "sykepenger-test.nav.no",
				urlString: "https://sykepenger-test.nav.no",
			},
		},
		{
			ingress: "http://localhost:3000",
			want: ingressWant{
				path:      "",
				domain:    "localhost:3000",
				urlString: "http://localhost:3000",
			},
		},
	} {
		t.Run(test.ingress, func(t *testing.T) {
			u, err := ingress.ParseIngress(test.ingress)
			assert.NoError(t, err)
			assert.Equal(t, test.want.path, u.Path())
			assert.Equal(t, test.want.domain, u.Host())
			assert.Equal(t, test.want.urlString, u.String())
		})
	}
}

func TestParseIngress_Invalid(t *testing.T) {
	for _, test := range []struct {
		name    string
		ingress string
	}{
		{
			name:    "empty",
			ingress: "",
		},
		{
			name:    "no scheme or domain",
			ingress: "/",
		},
		{
			name:    "invalid scheme",
			ingress: "test://example.com",
		},
	} {
		t.Run(test.ingress, func(t *testing.T) {
			_, err := ingress.ParseIngress(test.ingress)
			assert.Error(t, err)
		})
	}
}

type ingressesWant struct {
	paths      []string
	hosts      []string
	urlStrings []string
}

func TestParseIngresses(t *testing.T) {
	for _, test := range []struct {
		name      string
		ingresses []string
		want      ingressesWant
	}{
		{
			name: "single ingress",
			ingresses: []string{
				"https://domain.wonderwall.io",
			},
			want: ingressesWant{
				paths:      []string{""},
				hosts:      []string{"domain.wonderwall.io"},
				urlStrings: []string{"https://domain.wonderwall.io"},
			},
		},
		{
			name: "multiple subdomains",
			ingresses: []string{
				"http://localhost:8080",
				"http://localhost:8080/",
				"https://domain.wonderwall.io",
				"https://domain.wonderwall.io/",
				"https://another-domain.wonderwall.io",
				"https://also.another-domain.wonderwall.io",
			},
			want: ingressesWant{
				paths: []string{""},
				hosts: []string{
					"localhost:8080",
					"domain.wonderwall.io",
					"another-domain.wonderwall.io",
					"also.another-domain.wonderwall.io",
				},
				urlStrings: []string{
					"http://localhost:8080",
					"https://domain.wonderwall.io",
					"https://another-domain.wonderwall.io",
					"https://also.another-domain.wonderwall.io",
				},
			},
		},
		{
			name: "multiple paths",
			ingresses: []string{
				"https://domain.wonderwall.io",
				"https://domain.wonderwall.io/path",
				"https://domain.wonderwall.io/another-path",
				"https://domain.wonderwall.io/path/another-path",
			},
			want: ingressesWant{
				paths: []string{
					"",
					"/path",
					"/another-path",
					"/path/another-path",
				},
				hosts: []string{"domain.wonderwall.io"},
				urlStrings: []string{
					"https://domain.wonderwall.io",
					"https://domain.wonderwall.io/path",
					"https://domain.wonderwall.io/another-path",
					"https://domain.wonderwall.io/path/another-path",
				},
			},
		},
		{
			name: "multiple subdomains and paths",
			ingresses: []string{
				"https://domain.wonderwall.io",
				"https://domain.wonderwall.io/path",
				"https://domain.wonderwall.io/path/another-path",
				"https://another-domain.wonderwall.io",
				"https://another-domain.wonderwall.io/path",
				"https://another-domain.wonderwall.io/path/another-path",
			},
			want: ingressesWant{
				paths: []string{
					"",
					"/path",
					"/path/another-path",
				},
				hosts: []string{
					"domain.wonderwall.io",
					"another-domain.wonderwall.io",
				},
				urlStrings: []string{
					"https://domain.wonderwall.io",
					"https://domain.wonderwall.io/path",
					"https://domain.wonderwall.io/path/another-path",
					"https://another-domain.wonderwall.io",
					"https://another-domain.wonderwall.io/path",
					"https://another-domain.wonderwall.io/path/another-path",
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{
				Ingresses: test.ingresses,
			}
			ingresses, err := ingress.ParseIngresses(cfg)
			assert.NoError(t, err)
			assert.ElementsMatch(t, ingresses.Paths(), test.want.paths)
			assert.ElementsMatch(t, ingresses.Hosts(), test.want.hosts)
			assert.ElementsMatch(t, ingresses.Strings(), test.want.urlStrings)
		})
	}
}

func TestParseIngresses_Invalid(t *testing.T) {
	for _, test := range []struct {
		name      string
		ingresses []string
	}{
		{
			name:      "no ingresses",
			ingresses: []string{},
		},
		{
			name:      "empty",
			ingresses: []string{""},
		},
		{
			name:      "no scheme or domain",
			ingresses: []string{"/"},
		},
		{
			name:      "invalid scheme",
			ingresses: []string{"test://example.com"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{
				Ingresses: test.ingresses,
			}
			_, err := ingress.ParseIngresses(cfg)
			assert.Error(t, err)
		})
	}
}

func TestIngresses_MatchingIngress(t *testing.T) {
	cfg := &config.Config{
		Ingresses: []string{
			"https://domain.wonderwall.io",
			"https://domain.wonderwall.io/path",
			"https://domain.wonderwall.io/path/another-path",
			"https://another-domain.wonderwall.io",
			"https://another-domain.wonderwall.io/path",
			"https://another-domain.wonderwall.io/path/another-path",
		},
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	assert.NoError(t, err)

	for _, test := range []struct {
		target string
		want   *ingressWant
	}{
		{
			target: "https://domain.wonderwall.io",
			want: &ingressWant{
				path:      "",
				domain:    "domain.wonderwall.io",
				urlString: "https://domain.wonderwall.io",
			},
		},
		{
			target: "https://domain.wonderwall.io/",
			want: &ingressWant{
				path:      "",
				domain:    "domain.wonderwall.io",
				urlString: "https://domain.wonderwall.io",
			},
		},
		{
			target: "https://domain.wonderwall.io/path/hello/yes/no",
			want: &ingressWant{
				path:      "/path",
				domain:    "domain.wonderwall.io",
				urlString: "https://domain.wonderwall.io/path",
			},
		},
		{
			target: "https://domain.wonderwall.io/path/another-path/hello",
			want: &ingressWant{
				path:      "/path/another-path",
				domain:    "domain.wonderwall.io",
				urlString: "https://domain.wonderwall.io/path/another-path",
			},
		},
		{
			target: "https://another-domain.wonderwall.io/test",
			want: &ingressWant{
				path:      "",
				domain:    "another-domain.wonderwall.io",
				urlString: "https://another-domain.wonderwall.io",
			},
		},
		{
			target: "https://another-domain.wonderwall.io/path/hello/yes/no",
			want: &ingressWant{
				path:      "/path",
				domain:    "another-domain.wonderwall.io",
				urlString: "https://another-domain.wonderwall.io/path",
			},
		},
		// no matches
		{
			target: "https://not.domain.wonderwall.io",
		},
		{
			target: "https://test.example.com/path",
		},
		{
			target: "http://localhost:3000/",
		},
	} {
		t.Run(test.target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.target, nil)
			match, ok := ingresses.MatchingIngress(req)
			if test.want != nil {
				assert.True(t, ok)
				assert.Equal(t, test.want.path, match.Path())
				assert.Equal(t, test.want.domain, match.Host())
				assert.Equal(t, test.want.urlString, match.String())
			} else {
				assert.False(t, ok)
			}
		})
	}
}

func TestIngresses_MatchingPath(t *testing.T) {
	cfg := &config.Config{
		Ingresses: []string{
			"https://domain.wonderwall.io",
			"https://domain.wonderwall.io/path",
			"https://domain.wonderwall.io/path/another-path",
		},
	}

	ingresses, err := ingress.ParseIngresses(cfg)
	assert.NoError(t, err)

	for _, test := range []struct {
		target string
		want   string
	}{
		{
			target: "https://domain.wonderwall.io",
			want:   "",
		},
		{
			target: "https://domain.wonderwall.io/",
			want:   "",
		},
		{
			target: "https://domain.wonderwall.io/path/hello/yes/no",
			want:   "/path",
		},
		{
			target: "https://domain.wonderwall.io/path/another-path/hello",
			want:   "/path/another-path",
		},
	} {
		t.Run(test.target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.target, nil)
			match := ingresses.MatchingPath(req)
			assert.Equal(t, test.want, match)
		})
	}
}
