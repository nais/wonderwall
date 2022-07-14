package loginstatus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
)

const (
	SameSiteMode = http.SameSiteDefaultMode
)

type Client interface {
	ExchangeToken(ctx context.Context, accessToken string) (*TokenResponse, error)
	SetCookie(w http.ResponseWriter, token *TokenResponse, opts cookie.Options)
	HasCookie(r *http.Request) bool
	ClearCookie(w http.ResponseWriter, opts cookie.Options)
	CookieOptions(opts cookie.Options) cookie.Options
}

func NewClient(config config.Loginstatus, httpClient *http.Client) Client {
	return client{
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

type client struct {
	config     config.Loginstatus
	httpClient *http.Client
}

func (c client) ExchangeToken(ctx context.Context, accessToken string) (*TokenResponse, error) {
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

func (c client) SetCookie(w http.ResponseWriter, token *TokenResponse, opts cookie.Options) {
	name := c.config.CookieName
	expiresIn := time.Duration(token.ExpiresIn) * time.Second

	opts = c.CookieOptions(opts).
		WithExpiresIn(expiresIn)

	newCookie := cookie.Make(name, token.AccessToken, opts)
	cookie.Set(w, newCookie)
}

func (c client) HasCookie(r *http.Request) bool {
	_, err := r.Cookie(c.config.CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return false
	}
	return true
}

func (c client) ClearCookie(w http.ResponseWriter, opts cookie.Options) {
	cookieName := c.config.CookieName
	opts = c.CookieOptions(opts)

	cookie.Clear(w, cookieName, opts)
}

func (c client) CookieOptions(opts cookie.Options) cookie.Options {
	domain := c.config.CookieDomain
	return opts.WithDomain(domain).
		WithSameSite(SameSiteMode).
		WithPath("/")
}

func request(ctx context.Context, url string, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func handleResponse(resp *http.Response) (*TokenResponse, error) {
	body, err := ioutil.ReadAll(resp.Body)
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
