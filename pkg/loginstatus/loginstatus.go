package loginstatus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
)

const (
	SameSiteMode           = http.SameSiteDefaultMode
	LoginserviceCookieName = "selvbetjening-idtoken"
)

func NewClient(config config.Loginstatus, httpClient *http.Client) *Loginstatus {
	return &Loginstatus{
		config:     config,
		httpClient: httpClient,
	}
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type Loginstatus struct {
	config     config.Loginstatus
	httpClient *http.Client
}

func (c *Loginstatus) NeedsResourceIndicator() bool {
	return c.Enabled() && len(c.ResourceIndicator()) > 0
}

func (c *Loginstatus) ResourceIndicator() string {
	return c.config.ResourceIndicator
}

func (c *Loginstatus) Enabled() bool {
	return c.config.Enabled
}

func (c *Loginstatus) ExchangeToken(ctx context.Context, accessToken string) (*TokenResponse, error) {
	req, err := request(ctx, c.config.TokenURL, accessToken)
	if err != nil {
		return nil, fmt.Errorf("creating request %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	tokenResponse, err := handleResponse(resp)
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func (c *Loginstatus) SetCookie(w http.ResponseWriter, token *TokenResponse, opts cookie.Options) {
	name := c.config.CookieName
	expiresIn := time.Duration(token.ExpiresIn) * time.Second

	opts = c.CookieOptions(opts).
		WithExpiresIn(expiresIn)

	newCookie := cookie.Make(name, token.AccessToken, opts)
	cookie.Set(w, newCookie)
}

func (c *Loginstatus) HasCookie(r *http.Request) bool {
	_, err := r.Cookie(c.config.CookieName)
	return !errors.Is(err, http.ErrNoCookie)
}

func (c *Loginstatus) ClearCookie(w http.ResponseWriter, opts cookie.Options) {
	cookieName := c.config.CookieName
	opts = c.CookieOptions(opts)

	cookie.Clear(w, cookieName, opts)
	cookie.Clear(w, LoginserviceCookieName, opts.WithSameSite(http.SameSiteNoneMode))
}

func (c *Loginstatus) CookieOptions(opts cookie.Options) cookie.Options {
	domain := c.config.CookieDomain
	return opts.WithDomain(domain).
		WithSameSite(SameSiteMode).
		WithPath("/")
}

func (c *Loginstatus) NeedsLogin(r *http.Request) bool {
	if c.config.Enabled && !c.HasCookie(r) {
		return true
	}

	return false
}

func request(ctx context.Context, url string, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func handleResponse(resp *http.Response) (*TokenResponse, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading server response: %w", err)
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		var errorResponse ErrorResponse
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return nil, fmt.Errorf("client error: HTTP %d: unmarshalling error response: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("client error: HTTP %d: %s: %s", resp.StatusCode, errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("server error: HTTP %d: %s", resp.StatusCode, body)
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling token response: %w", err)
	}

	return &tokenResponse, nil
}
