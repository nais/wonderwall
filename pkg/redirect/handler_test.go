package redirect_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/redirect"
)

type expected struct {
	canonical string
	clean     string
}

func TestDefaultHandler(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"http://wonderwall",
		"http://wonderwall/some-path",
	}
	ingresses := mock.Ingresses(cfg)

	h := redirect.NewDefaultHandler(ingresses)

	for _, tt := range []struct {
		name     string
		url      string
		expected expected
	}{
		{
			name: "no redirect param",
			url:  "/",
			expected: expected{
				canonical: "/",
				clean:     "/",
			},
		},
		{
			name: "empty redirect param",
			url:  "/?redirect=",
			expected: expected{
				canonical: "/",
				clean:     "/?redirect=",
			},
		},
		{
			name: "no redirect param, context path",
			url:  "/some-path",
			expected: expected{
				canonical: "/some-path",
				clean:     "/some-path",
			},
		},
		{
			name: "empty redirect param, context path",
			url:  "/some-path?redirect=",
			expected: expected{
				canonical: "/some-path",
				clean:     "/some-path?redirect=",
			},
		},
		{
			name: "with query parameters",
			url:  "/?redirect=%2Fpath%3Fgnu%3Dnotunix",
			expected: expected{
				canonical: "/path?gnu=notunix",
				clean:     "/?redirect=%2Fpath%3Fgnu%3Dnotunix",
			},
		},
		{
			name: "with multiple query parameters",
			url:  "/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			expected: expected{
				canonical: "/path?gnu=notunix&foo=bar",
				clean:     "/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			},
		},
		{
			name: "relative url with absolute url in redirect",
			url:  "/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "/some-path?with=query",
				clean:     "/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			},
		},
		{
			name: "with unescaped query parameters",
			url:  "/some-path?redirect=/path?gnu=notunix&foo=bar",
			expected: expected{
				canonical: "/path?gnu=notunix",
				clean:     "/some-path?redirect=/path?gnu=notunix&foo=bar",
			},
		},
		{
			name: "absolute url with different domain",
			url:  "http://not-wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "/path",
				clean:     "/",
			},
		},
		{
			name: "absolute url with context path",
			url:  "http://wonderwall/some-path?redirect=%2Fpath",
			expected: expected{
				canonical: "/path",
				clean:     "/some-path",
			},
		},
		{
			name: "absolute url with query parameters",
			url:  "http://wonderwall/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			expected: expected{
				canonical: "/path?gnu=notunix&foo=bar",
				clean:     "/some-path",
			},
		},
		{
			name: "absolute url with subdomain",
			url:  "http://app.wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "/path",
				clean:     "/",
			},
		},
		{
			name: "absolute url with absolute url in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fwonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "/some-path?with=query",
				clean:     "/",
			},
		},
		{
			name: "absolute url with different domain in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "/some-path?with=query",
				clean:     "/",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := mock.NewGetRequest(tt.url, ingresses)
			assert.Equal(t, tt.expected.canonical, h.Canonical(r))
			assert.Equal(t, tt.expected.clean, h.Clean(r, tt.url))
		})
	}
}

func TestSSOServerHandler(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"http://wonderwall",
		"http://wonderwall/some-path",
	}
	cfg.SSO.Enabled = true
	cfg.SSO.Domain = "wonderwall"
	cfg.SSO.ServerDefaultRedirectURL = "http://fallback.wonderwall"
	ingresses := mock.Ingresses(cfg)

	h, err := redirect.NewSSOServerHandler(cfg)
	require.NoError(t, err)

	for _, tt := range []struct {
		name     string
		url      string
		expected expected
	}{
		{
			name: "no redirect param",
			url:  "/",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "empty redirect param",
			url:  "/?redirect=",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "no redirect param, context path",
			url:  "/some-path",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "empty redirect param, context path",
			url:  "/some-path?redirect=",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "with query parameters",
			url:  "/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "relative url with absolute url in redirect",
			url:  "/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "with unescaped query parameters",
			url:  "/some-path?redirect=/path?gnu=notunix&foo=bar",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "absolute url",
			url:  "http://wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://wonderwall/?redirect=%2Fpath",
			},
		},
		{
			name: "absolute url, different domain",
			url:  "http://not-wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://fallback.wonderwall",
			},
		},
		{
			name: "absolute url with context path",
			url:  "http://wonderwall/some-path?redirect=%2Fpath",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://wonderwall/some-path?redirect=%2Fpath",
			},
		},
		{
			name: "absolute url with query parameters",
			url:  "http://wonderwall/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://wonderwall/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			},
		},
		{
			name: "absolute url, subdomain",
			url:  "http://app.wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://app.wonderwall/?redirect=%2Fpath",
			},
		},
		{
			name: "absolute url, nested subdomain",
			url:  "http://some.app.wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://some.app.wonderwall/?redirect=%2Fpath",
			},
		},
		{
			name: "absolute url in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fwonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://wonderwall/some-path?with=query",
				clean:     "http://wonderwall/?redirect=http%3A%2F%2Fwonderwall%2Fsome-path%3Fwith%3Dquery",
			},
		},
		{
			name: "absolute url with different domain in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://fallback.wonderwall",
				clean:     "http://wonderwall/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			},
		},
		{
			name: "absolute url with subdomain in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fapp.wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://app.wonderwall/some-path?with=query",
				clean:     "http://wonderwall/?redirect=http%3A%2F%2Fapp.wonderwall%2Fsome-path%3Fwith%3Dquery",
			},
		},
		{
			name: "absolute url with nested subdomain in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fsome.app.wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://some.app.wonderwall/some-path?with=query",
				clean:     "http://wonderwall/?redirect=http%3A%2F%2Fsome.app.wonderwall%2Fsome-path%3Fwith%3Dquery",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := mock.NewGetRequest(tt.url, ingresses)
			assert.Equal(t, tt.expected.canonical, h.Canonical(r))
			assert.Equal(t, tt.expected.clean, h.Clean(r, tt.url))
		})
	}
}

func TestSSOProxyHandler(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"http://app.wonderwall",
	}
	cfg.SSO.Enabled = true
	cfg.SSO.ServerURL = "http://sso.wonderwall"
	ingresses := mock.Ingresses(cfg)

	h := redirect.NewSSOProxyHandler(ingresses)

	for _, tt := range []struct {
		name     string
		url      string
		expected expected
	}{
		{
			name: "no redirect param",
			url:  "/",
			expected: expected{
				canonical: "http://app.wonderwall",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "empty redirect param",
			url:  "/?redirect=",
			expected: expected{
				canonical: "http://app.wonderwall",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "no redirect param, context path",
			url:  "/some-path",
			expected: expected{
				canonical: "http://app.wonderwall",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "empty redirect param, context path",
			url:  "/some-path?redirect=",
			expected: expected{
				canonical: "http://app.wonderwall",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "with query parameters",
			url:  "/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			expected: expected{
				canonical: "http://app.wonderwall/path?gnu=notunix&foo=bar",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "relative url with absolute url in redirect",
			url:  "/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://app.wonderwall/some-path?with=query",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "with unescaped query parameters",
			url:  "/some-path?redirect=/path?gnu=notunix&foo=bar",
			expected: expected{
				canonical: "http://app.wonderwall/path?gnu=notunix",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url",
			url:  "http://wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "http://app.wonderwall/path",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url, different domain",
			url:  "http://not-wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "http://app.wonderwall/path",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url with context path",
			url:  "http://wonderwall/some-path?redirect=%2Fpath",
			expected: expected{
				canonical: "http://app.wonderwall/path",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url with query parameters",
			url:  "http://wonderwall/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix",
			expected: expected{
				canonical: "http://app.wonderwall/path?gnu=notunix",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url with multiple query parameters",
			url:  "http://wonderwall/some-path?redirect=%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			expected: expected{
				canonical: "http://app.wonderwall/path?gnu=notunix&foo=bar",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url, different subdomain",
			url:  "http://another-app.wonderwall/?redirect=%2Fpath",
			expected: expected{
				canonical: "http://app.wonderwall/path",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url in redirect",
			url:  "http://app.wonderwall/path?redirect=http%3A%2F%2Fwonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://app.wonderwall/some-path?with=query",
				clean:     "http://app.wonderwall/path?redirect=http%3A%2F%2Fwonderwall%2Fsome-path%3Fwith%3Dquery",
			},
		},
		{
			name: "absolute url with different domain in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fnot-wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://app.wonderwall/some-path?with=query",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url with subdomain in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fanother-app.wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://app.wonderwall/some-path?with=query",
				clean:     "http://app.wonderwall",
			},
		},
		{
			name: "absolute url with nested subdomain in redirect",
			url:  "http://wonderwall/?redirect=http%3A%2F%2Fsome.app.wonderwall%2Fsome-path%3Fwith%3Dquery",
			expected: expected{
				canonical: "http://app.wonderwall/some-path?with=query",
				clean:     "http://app.wonderwall",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := mock.NewGetRequest(tt.url, ingresses)
			assert.Equal(t, tt.expected.canonical, h.Canonical(r))
			assert.Equal(t, tt.expected.clean, h.Clean(r, tt.url))
		})
	}
}
