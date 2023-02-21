package url_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

func TestLogin(t *testing.T) {
	for _, test := range []struct {
		name           string
		targetURL      string
		redirectTarget string
		want           string
	}{
		{
			name:           "root path",
			targetURL:      "https://sso.wonderwall",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "https://sso.wonderwall/oauth2/login?redirect=https%3A%2F%2Ftest.example.com%3Fsome%3Dparam%26other%3Dparam2",
		},
		{
			name:           "with prefix",
			targetURL:      "https://sso.wonderwall/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "https://sso.wonderwall/path/oauth2/login?redirect=https%3A%2F%2Ftest.example.com%3Fsome%3Dparam%26other%3Dparam2",
		},
		{
			name:           "we need to go deeper",
			targetURL:      "https://sso.wonderwall/deeper/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "https://sso.wonderwall/deeper/path/oauth2/login?redirect=https%3A%2F%2Ftest.example.com%3Fsome%3Dparam%26other%3Dparam2",
		},
		{
			name:           "relative redirect target",
			targetURL:      "https://sso.wonderwall",
			redirectTarget: "/path?some=param&other=param2",
			want:           "https://sso.wonderwall/oauth2/login?redirect=%2Fpath%3Fsome%3Dparam%26other%3Dparam2",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			targetURL, err := url.Parse(test.targetURL)
			assert.NoError(t, err)

			loginUrl := urlpkg.Login(targetURL, test.redirectTarget)
			assert.Equal(t, test.want, loginUrl)
		})
	}
}

func TestLoginRelative(t *testing.T) {
	for _, test := range []struct {
		name           string
		prefix         string
		redirectTarget string
		want           string
	}{
		{
			name:           "no prefix",
			prefix:         "",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/oauth2/login?redirect=https%3A%2F%2Ftest.example.com%3Fsome%3Dparam%26other%3Dparam2",
		},
		{
			name:           "with prefix",
			prefix:         "/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/path/oauth2/login?redirect=https%3A%2F%2Ftest.example.com%3Fsome%3Dparam%26other%3Dparam2",
		},
		{
			name:           "we need to go deeper",
			prefix:         "/deeper/path",
			redirectTarget: "https://test.example.com?some=param&other=param2",
			want:           "/deeper/path/oauth2/login?redirect=https%3A%2F%2Ftest.example.com%3Fsome%3Dparam%26other%3Dparam2",
		},
		{
			name:           "relative target",
			prefix:         "",
			redirectTarget: "/path?some=param&other=param2",
			want:           "/oauth2/login?redirect=%2Fpath%3Fsome%3Dparam%26other%3Dparam2",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			loginUrl := urlpkg.LoginRelative(test.prefix, test.redirectTarget)
			assert.Equal(t, test.want, loginUrl)
		})
	}
}

func TestLoginCallback(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"https://nav.no",
		"https://nav.no/test",
		"https://nav.no/dagpenger",
		"https://nav.no/dagpenger/soknad",
	}
	ingresses := mock.Ingresses(cfg)

	for _, test := range []struct {
		input   string
		want    string
		wantErr bool
	}{
		{
			input: "https://nav.no/",
			want:  "https://nav.no/oauth2/callback",
		},
		{
			input: "https://nav.no/test",
			want:  "https://nav.no/test/oauth2/callback",
		},
		{
			input: "https://nav.no/dagpenger",
			want:  "https://nav.no/dagpenger/oauth2/callback",
		},
		{
			input: "https://nav.no/dagpenger/soknad",
			want:  "https://nav.no/dagpenger/soknad/oauth2/callback",
		},
		{
			input:   "https://not-nav.no/",
			wantErr: true,
		},
	} {
		t.Run(test.input, func(t *testing.T) {
			req := mock.NewGetRequest(test.input, ingresses)

			actual, err := urlpkg.LoginCallback(req)
			if test.wantErr {
				assert.ErrorIs(t, err, urlpkg.ErrNoMatchingIngress)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.want, actual)
			}
		})
	}
}

func TestLogoutCallback(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"https://nav.no",
		"https://nav.no/test",
		"https://nav.no/dagpenger",
		"https://nav.no/dagpenger/soknad",
	}
	ingresses := mock.Ingresses(cfg)

	for _, test := range []struct {
		input   string
		want    string
		wantErr bool
	}{
		{
			input: "https://nav.no/",
			want:  "https://nav.no/oauth2/logout/callback",
		},
		{
			input: "https://nav.no/test",
			want:  "https://nav.no/test/oauth2/logout/callback",
		},
		{
			input: "https://nav.no/dagpenger",
			want:  "https://nav.no/dagpenger/oauth2/logout/callback",
		},
		{
			input: "https://nav.no/dagpenger/soknad",
			want:  "https://nav.no/dagpenger/soknad/oauth2/logout/callback",
		},
		{
			input:   "https://not-nav.no/",
			wantErr: true,
		},
	} {
		t.Run(test.input, func(t *testing.T) {
			req := mock.NewGetRequest(test.input, ingresses)

			actual, err := urlpkg.LogoutCallback(req)
			if test.wantErr {
				assert.ErrorIs(t, err, urlpkg.ErrNoMatchingIngress)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.want, actual)
			}
		})
	}
}

func TestMatchingPath(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"http://wonderwall",
		"http://wonderwall/some-path",
	}
	ingresses := mock.Ingresses(cfg)

	t.Run("matching ingress path", func(t *testing.T) {
		for _, tt := range []struct {
			target   string
			expected string
		}{
			{
				target:   "/",
				expected: "/",
			},
			{
				target:   "/some-path",
				expected: "/some-path",
			},
			{
				target:   "/some-path/some-subpath",
				expected: "/some-path",
			},
			{
				target:   "http://wonderwall",
				expected: "/",
			},
			{
				target:   "http://wonderwall/some-path",
				expected: "/some-path",
			},
			{
				target:   "http://wonderwall/some-path/some-subpath",
				expected: "/some-path",
			},
		} {
			t.Run(tt.target, func(t *testing.T) {
				req := mock.NewGetRequest(tt.target, ingresses)
				assert.Equal(t, tt.expected, urlpkg.MatchingPath(req).String())
			})
		}
	})

	t.Run("no matching path should fall back to root", func(t *testing.T) {
		req := mock.NewGetRequest("http://wonderwall/no-match", ingresses)
		assert.Equal(t, "/", urlpkg.MatchingPath(req).String())
	})
}

func TestMatchingIngress(t *testing.T) {
	cfg := mock.Config()
	cfg.Ingresses = []string{
		"http://wonderwall",
		"http://wonderwall/some-path",
	}
	ingresses := mock.Ingresses(cfg)

	t.Run("matching ingress path", func(t *testing.T) {
		for _, tt := range []struct {
			target   string
			expected string
		}{
			{
				target:   "http://wonderwall",
				expected: "http://wonderwall",
			},
			{
				target:   "http://wonderwall/",
				expected: "http://wonderwall",
			},
			{
				target:   "http://wonderwall/?val1=foo&val2=bar",
				expected: "http://wonderwall",
			},
			{
				target:   "http://wonderwall/some-path",
				expected: "http://wonderwall/some-path",
			},
			{
				target:   "http://wonderwall/some-path/",
				expected: "http://wonderwall/some-path",
			},
			{
				target:   "http://wonderwall/some-path/some-subpath",
				expected: "http://wonderwall/some-path",
			},
		} {
			t.Run(tt.target, func(t *testing.T) {
				req := mock.NewGetRequest(tt.target, ingresses)

				actual, err := urlpkg.MatchingIngress(req)
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, actual.String())
			})
		}
	})

	t.Run("relative URLs should return error", func(t *testing.T) {
		for _, target := range []string{
			"/",
			"/some-path",
			"/some-path/some-subpath",
		} {
			t.Run(target, func(t *testing.T) {
				req := mock.NewGetRequest(target, ingresses)

				_, err := urlpkg.MatchingIngress(req)
				assert.ErrorIs(t, err, urlpkg.ErrNoMatchingIngress)
			})
		}
	})

	t.Run("no matching ingress should return error", func(t *testing.T) {
		req := mock.NewGetRequest("http://not-wonderwall", ingresses)

		_, err := urlpkg.MatchingIngress(req)
		assert.ErrorIs(t, err, urlpkg.ErrNoMatchingIngress)
	})
}
