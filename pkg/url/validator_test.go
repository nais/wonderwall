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

func TestAbsoluteValidator_IsValidRedirect(t *testing.T) {
	cfg := mock.Config()
	cfg.SSO.Domain = "wonderwall"
	ingresses := mock.Ingresses(cfg)
	r := mock.NewGetRequest("https://wonderwall", ingresses)

	allowedDomains := []string{
		cfg.SSO.Domain,
		"www.whitelisteddomain.tld",
	}
	absoluteValidator := urlpkg.NewAbsoluteValidator(allowedDomains)

	t.Run("open redirects list", func(t *testing.T) {
		file, err := os.Open("testdata/open-redirects.txt")
		require.NoError(t, err)
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			input := url.QueryEscape(scanner.Text())
			assert.False(t, absoluteValidator.IsValidRedirect(r, input), fmt.Sprintf("%q should not pass validation", input))
		}

		err = scanner.Err()
		require.NoError(t, err)
	})

	for _, tt := range []struct {
		name          string
		redirectParam string
		wantErr       bool
	}{
		{
			name:          "absolute url with parameters",
			redirectParam: "https://wonderwall/path/to/redirect?val1=foo&val2=bar",
		},
		{
			name:          "absolute url with http scheme",
			redirectParam: "https://wonderwall/path/to/redirect?val1=foo&val2=bar",
		},
		{
			name:          "absolute url with non-http scheme",
			redirectParam: "ftp://wonderwall/path/to/redirect?val1=foo&val2=bar",
			wantErr:       true,
		},
		{
			name:          "root url with trailing slash",
			redirectParam: "https://wonderwall/",
		},
		{
			name:          "root url without trailing slash",
			redirectParam: "https://wonderwall",
		},
		{
			name:          "url path with trailing slash",
			redirectParam: "https://wonderwall/path/",
		},
		{
			name:          "url path without trailing slash",
			redirectParam: "https://wonderwall/path",
		},
		{
			name:          "different domain",
			redirectParam: "https://not-wonderwall/path/to/redirect?val1=foo&val2=bar",
			wantErr:       true,
		},
		{
			name:          "absolute path",
			redirectParam: "/path",
			wantErr:       true,
		},
		{
			name:          "absolute path with query parameters",
			redirectParam: "/path?gnu=notunix",
			wantErr:       true,
		},
		{
			name:          "relative path",
			redirectParam: "path",
			wantErr:       true,
		},
		{
			name:          "relative path with query parameters",
			redirectParam: "path?gnu=notunix",
			wantErr:       true,
		},
		{
			name:          "double-url encoded path",
			redirectParam: "%2Fpath",
			wantErr:       true,
		},
		{
			name:          "double-url encoded path and query parameters",
			redirectParam: "%2Fpath%3Fgnu%3Dnotunix",
			wantErr:       true,
		},
		{
			name:          "double-url encoded url",
			redirectParam: "http%3A%2F%2Flocalhost%3A8080%2Fpath",
			wantErr:       true,
		},
		{
			name:          "double-url encoded url and multiple query parameters",
			redirectParam: "http%3A%2F%2Flocalhost%3A8080%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			wantErr:       true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			actual := absoluteValidator.IsValidRedirect(r, tt.redirectParam)
			if tt.wantErr {
				assert.False(t, actual)
			} else {
				assert.True(t, actual)
			}
		})
	}
}

func TestRelativeValidator_IsValidRedirect(t *testing.T) {
	cfg := mock.Config()
	cfg.SSO.Domain = "wonderwall"
	ingresses := mock.Ingresses(cfg)
	r := mock.NewGetRequest("https://wonderwall", ingresses)

	allowedDomains := []string{
		cfg.SSO.Domain,
		"www.whitelisteddomain.tld",
	}
	relativeValidator := urlpkg.NewRelativeValidator(allowedDomains)

	t.Run("open redirects list", func(t *testing.T) {
		file, err := os.Open("testdata/open-redirects.txt")
		require.NoError(t, err)
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			input := url.QueryEscape(scanner.Text())
			assert.False(t, relativeValidator.IsValidRedirect(r, input), fmt.Sprintf("%q should not pass validation", input))
		}

		err = scanner.Err()
		require.NoError(t, err)
	})

	for _, tt := range []struct {
		name          string
		redirectParam string
		wantErr       bool
	}{
		{
			name:          "absolute url with parameters",
			redirectParam: "https://wonderwall/path/to/redirect?val1=foo&val2=bar",
			wantErr:       true,
		},
		{
			name:          "absolute url with http scheme",
			redirectParam: "https://wonderwall/path/to/redirect?val1=foo&val2=bar",
			wantErr:       true,
		},
		{
			name:          "absolute url with non-http scheme",
			redirectParam: "ftp://wonderwall/path/to/redirect?val1=foo&val2=bar",
			wantErr:       true,
		},
		{
			name:          "root url with trailing slash",
			redirectParam: "https://wonderwall/",
			wantErr:       true,
		},
		{
			name:          "root url without trailing slash",
			redirectParam: "https://wonderwall",
			wantErr:       true,
		},
		{
			name:          "url path with trailing slash",
			redirectParam: "https://wonderwall/path/",
			wantErr:       true,
		},
		{
			name:          "url path without trailing slash",
			redirectParam: "https://wonderwall/path",
			wantErr:       true,
		},
		{
			name:          "different domain",
			redirectParam: "https://not-wonderwall/path/to/redirect?val1=foo&val2=bar",
			wantErr:       true,
		},
		{
			name:          "absolute path",
			redirectParam: "/path",
		},
		{
			name:          "absolute path with query parameters",
			redirectParam: "/path?gnu=notunix",
		},
		{
			name:          "relative path",
			redirectParam: "path",
			wantErr:       true,
		},
		{
			name:          "relative path with query parameters",
			redirectParam: "path?gnu=notunix",
			wantErr:       true,
		},
		{
			name:          "double-url encoded path",
			redirectParam: "%2Fpath",
			wantErr:       true,
		},
		{
			name:          "double-url encoded path and query parameters",
			redirectParam: "%2Fpath%3Fgnu%3Dnotunix",
			wantErr:       true,
		},
		{
			name:          "double-url encoded url",
			redirectParam: "http%3A%2F%2Flocalhost%3A8080%2Fpath",
			wantErr:       true,
		},
		{
			name:          "double-url encoded url and multiple query parameters",
			redirectParam: "http%3A%2F%2Flocalhost%3A8080%2Fpath%3Fgnu%3Dnotunix%26foo%3Dbar",
			wantErr:       true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			actual := relativeValidator.IsValidRedirect(r, tt.redirectParam)
			if tt.wantErr {
				assert.False(t, actual)
			} else {
				assert.True(t, actual)
			}
		})
	}
}
