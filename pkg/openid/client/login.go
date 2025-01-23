package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	urllib "net/url"
	"slices"
	stringslib "strings"

	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/acr"
	"github.com/nais/wonderwall/pkg/strings"
	"github.com/nais/wonderwall/pkg/url"
)

const (
	LocaleURLParameter        = "locale"
	SecurityLevelURLParameter = "level"
	PromptURLParameter        = "prompt"
)

var (
	ErrInvalidSecurityLevel  = errors.New("InvalidSecurityLevel")
	ErrInvalidLocale         = errors.New("InvalidLocale")
	ErrInvalidPrompt         = errors.New("InvalidPrompt")
	ErrInvalidLoginParameter = errors.New("InvalidLoginParameter")

	PromptAllowedValues = []string{"login", "select_account"}
)

type Login struct {
	openid.AuthorizationCodeParams
	AuthCodeURL string
	Cookie      openid.LoginCookie
}

func (c *Client) Login(r *http.Request) (*Login, error) {
	request, err := c.newAuthorizationCodeParams(r)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	authCodeURL, err := c.authCodeURL(r.Context(), request)
	if err != nil {
		return nil, fmt.Errorf("login: generating auth code url: %w", err)
	}

	return &Login{
		AuthCodeURL:             authCodeURL,
		AuthorizationCodeParams: request,
		Cookie:                  request.Cookie(),
	}, nil
}

func (c *Client) newAuthorizationCodeParams(r *http.Request) (openid.AuthorizationCodeParams, error) {
	var req openid.AuthorizationCodeParams

	callbackURL, err := url.LoginCallback(r)
	if err != nil {
		return req, fmt.Errorf("generating callback url: %w", err)
	}

	acrParam, err := getAcrParam(c, r)
	if err != nil {
		return req, fmt.Errorf("%w: %w", ErrInvalidSecurityLevel, err)
	}

	locale, err := getLocaleParam(c, r)
	if err != nil {
		return req, fmt.Errorf("%w: %w", ErrInvalidLocale, err)
	}

	prompt, err := getPromptParam(r)
	if err != nil {
		return req, fmt.Errorf("%w: %w", ErrInvalidPrompt, err)
	}

	nonce, err := strings.GenerateBase64(32)
	if err != nil {
		return req, fmt.Errorf("creating nonce: %w", err)
	}

	state, err := strings.GenerateBase64(32)
	if err != nil {
		return req, fmt.Errorf("creating state: %w", err)
	}

	resource := c.cfg.Client().ResourceIndicator()
	codeVerifier := oauth2.GenerateVerifier()

	return openid.AuthorizationCodeParams{
		AcrValues:    acrParam,
		ClientID:     c.oauth2Config.ClientID,
		CodeVerifier: codeVerifier,
		Nonce:        nonce,
		Prompt:       prompt,
		RedirectURI:  callbackURL,
		Resource:     resource,
		Scope:        c.oauth2Config.Scopes,
		State:        state,
		UILocales:    locale,
	}, nil
}

func (c *Client) authCodeURL(ctx context.Context, request openid.AuthorizationCodeParams) (string, error) {
	var authCodeURL string

	if c.cfg.Provider().PushedAuthorizationRequestEndpoint() == "" {
		opts := request.AuthParams().AuthCodeOptions()

		// TODO: replace with separate function
		authCodeURL = c.oauth2Config.AuthCodeURL(request.State, opts...)
	} else {
		clientAuthParams, err := c.ClientAuthenticationParams()
		if err != nil {
			return "", fmt.Errorf("generating client authentication parameters: %w", err)
		}

		endpoint := c.cfg.Provider().PushedAuthorizationRequestEndpoint()
		body, err := c.oauthPostRequest(ctx, endpoint, request.AuthParams().
			Merge(clientAuthParams).
			URLValues().
			Encode())
		if err != nil {
			return "", err
		}

		var pushedAuthorizationResponse openid.PushedAuthorizationResponse
		if err := json.Unmarshal(body, &pushedAuthorizationResponse); err != nil {
			return "", fmt.Errorf("unmarshalling token response: %w", err)
		}

		// TODO: this can a separate function to replace oauth2config.AuthCodeURL
		v := urllib.Values{
			"client_id":   {c.oauth2Config.ClientID},
			"request_uri": {pushedAuthorizationResponse.RequestUri},
		}
		var buf bytes.Buffer
		buf.WriteString(c.oauth2Config.Endpoint.AuthURL)
		if stringslib.Contains(c.oauth2Config.Endpoint.AuthURL, "?") {
			buf.WriteByte('&')
		} else {
			buf.WriteByte('?')
		}
		buf.WriteString(v.Encode())
		authCodeURL = buf.String()
	}

	return authCodeURL, nil
}

func (l *Login) SetCookie(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter, canonicalRedirect string) error {
	l.Cookie.Referer = canonicalRedirect

	loginCookieJson, err := json.Marshal(l.Cookie)
	if err != nil {
		return fmt.Errorf("marshalling login cookie: %w", err)
	}

	value := string(loginCookieJson)

	return cookie.EncryptAndSet(w, cookie.Login, value, opts, crypter)
}

func getAcrParam(c *Client, r *http.Request) (string, error) {
	defaultValue := c.cfg.Client().ACRValues()
	if len(defaultValue) == 0 {
		return "", nil
	}

	paramValue := r.URL.Query().Get(SecurityLevelURLParameter)
	if len(paramValue) == 0 {
		paramValue = defaultValue
	}

	supported := c.cfg.Provider().ACRValuesSupported()
	if supported.Contains(paramValue) {
		return paramValue, nil
	}

	translatedAcr, ok := acr.IDPortenLegacyMapping[paramValue]
	if ok && supported.Contains(translatedAcr) {
		return translatedAcr, nil
	}

	return "", fmt.Errorf("%w: invalid value for %s=%s (must be one of '%s')", ErrInvalidLoginParameter, SecurityLevelURLParameter, paramValue, supported)
}

func getLocaleParam(c *Client, r *http.Request) (string, error) {
	defaultValue := c.cfg.Client().UILocales()
	if len(defaultValue) == 0 {
		return "", nil
	}

	paramValue := r.URL.Query().Get(LocaleURLParameter)
	if len(paramValue) == 0 {
		paramValue = defaultValue
	}

	supported := c.cfg.Provider().UILocalesSupported()
	if supported.Contains(paramValue) {
		return paramValue, nil
	}

	return "", fmt.Errorf("%w: invalid value for %s=%s (must be one of '%s')", ErrInvalidLoginParameter, LocaleURLParameter, paramValue, supported)
}

func getPromptParam(r *http.Request) (string, error) {
	paramValue := r.URL.Query().Get(PromptURLParameter)
	if len(paramValue) == 0 {
		return "", nil
	}

	if slices.Contains(PromptAllowedValues, paramValue) {
		return paramValue, nil
	}

	return "", fmt.Errorf("%w: invalid value for %s=%s (must be one of '%s')", ErrInvalidLoginParameter, PromptURLParameter, paramValue, PromptAllowedValues)
}
