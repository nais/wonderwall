package url_test

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/pkg/mock"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

func TestValidator_IsValidRedirect(t *testing.T) {
	cfg := mock.Config()
	cfg.SSO.Domain = "wonderwall"
	ingresses := mock.Ingresses(cfg)
	r := mock.NewGetRequest("https://wonderwall", ingresses)

	allowedDomains := []string{
		cfg.SSO.Domain,
		"www.whitelisteddomain.tld",
	}
	absoluteValidator := urlpkg.NewValidator(urlpkg.Absolute, allowedDomains)
	relativeValidator := urlpkg.NewValidator(urlpkg.Relative, allowedDomains)

	t.Run("open redirects list", func(t *testing.T) {
		file, err := os.Open("testdata/open-redirects.txt")
		require.NoError(t, err)
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			input := url.QueryEscape(scanner.Text())
			assert.False(t, absoluteValidator.IsValidRedirect(r, input), fmt.Sprintf("%q should not pass validation", input))
			assert.False(t, relativeValidator.IsValidRedirect(r, input), fmt.Sprintf("%q should not pass validation", input))
		}

		err = scanner.Err()
		require.NoError(t, err)
	})

	for _, tt := range []struct {
		name          string
		redirectParam string
		urlType       urlpkg.Type
		wantErr       bool // expect error regardless of validator type
	}{
		{
			name:          "absolute url with parameters",
			redirectParam: "https://wonderwall/path/to/redirect?val1=foo&val2=bar",
			urlType:       urlpkg.Absolute,
		},
		{
			name:          "absolute url with http scheme",
			redirectParam: "https://wonderwall/path/to/redirect?val1=foo&val2=bar",
			urlType:       urlpkg.Absolute,
		},
		{
			name:          "absolute url with non-http scheme",
			redirectParam: "ftp://wonderwall/path/to/redirect?val1=foo&val2=bar",
			urlType:       urlpkg.Absolute,
			wantErr:       true,
		},
		{
			name:          "root url with trailing slash",
			redirectParam: "https://wonderwall/",
			urlType:       urlpkg.Absolute,
		},
		{
			name:          "root url without trailing slash",
			redirectParam: "https://wonderwall",
			urlType:       urlpkg.Absolute,
		},
		{
			name:          "url path with trailing slash",
			redirectParam: "https://wonderwall/path/",
			urlType:       urlpkg.Absolute,
		},
		{
			name:          "url path without trailing slash",
			redirectParam: "https://wonderwall/path",
			urlType:       urlpkg.Absolute,
		},
		{
			name:          "different domain",
			redirectParam: "https://not-wonderwall/path/to/redirect?val1=foo&val2=bar",
			urlType:       urlpkg.Absolute,
			wantErr:       true,
		},
		{
			name:          "absolute path",
			redirectParam: "/path",
			urlType:       urlpkg.Relative,
		},
		{
			name:          "absolute path with query parameters",
			redirectParam: "/path?gnu=notunix",
			urlType:       urlpkg.Relative,
		},
		{
			name:          "relative path",
			redirectParam: "path",
			urlType:       urlpkg.Relative,
			wantErr:       true,
		},
		{
			name:          "relative path with query parameters",
			redirectParam: "path?gnu=notunix",
			urlType:       urlpkg.Relative,
			wantErr:       true,
		},
		{
			name:          "double-url encoded path",
			redirectParam: "%2Fpath",
			urlType:       urlpkg.Relative,
			wantErr:       true,
		},
		{
			name:          "double-url encoded path and query parameters",
			redirectParam: "%2Fpath%3Fgnu%3Dnotunix",
			urlType:       urlpkg.Relative,
			wantErr:       true,
		},
		{
			name:          "double-url encoded url",
			redirectParam: "http%3A%2F%2Flocalhost%3A8080%2Fpath",
			urlType:       urlpkg.Relative,
			wantErr:       true,
		},
		{
			name:          "double-url encoded url and multiple query parameters",
			redirectParam: "http%3A%2F%2Flocalhost%3A8080%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			urlType:       urlpkg.Relative,
			wantErr:       true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.urlType {
			case urlpkg.Relative:
				actual := relativeValidator.IsValidRedirect(r, tt.redirectParam)
				if tt.wantErr {
					assert.False(t, actual)
				} else {
					assert.True(t, actual)
				}
			case urlpkg.Absolute:
				actual := absoluteValidator.IsValidRedirect(r, tt.redirectParam)
				if tt.wantErr {
					assert.False(t, actual)
				} else {
					assert.True(t, actual)
				}
			default:
				assert.FailNow(t, "invalid url type: %s", tt.urlType)
			}
		})
	}
}
