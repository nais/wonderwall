package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

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
	MaxAgeURLParameter        = "max_age"
)

var (
	ErrInvalidSecurityLevel  = errors.New("InvalidSecurityLevel")
	ErrInvalidLocale         = errors.New("InvalidLocale")
	ErrInvalidPrompt         = errors.New("InvalidPrompt")
	ErrInvalidLoginParameter = errors.New("InvalidLoginParameter")

	// LoginParameterMapping maps incoming login parameters to OpenID Connect parameters
	LoginParameterMapping = map[string]string{
		LocaleURLParameter:        "ui_locales",
		SecurityLevelURLParameter: "acr_values",
	}

	PromptAllowedValues = []string{"login", "select_account"}
)

type Login struct {
	AuthCodeURL string
	Acr         string
	Locale      string
	Prompt      string
	*openid.LoginCookie
}

type authorizationRequest struct {
	acr          string
	callbackURL  string
	codeVerifier string
	locale       string
	nonce        string
	prompt       string
	state        string
}

// TODO: remove indirection layer
func NewLogin(c *Client, r *http.Request) (*Login, error) {
	request, err := c.newAuthorizationRequest(r)
	if err != nil {
		return nil, err
	}

	authCodeURL, err := c.authCodeURL(r.Context(), request)
	if err != nil {
		return nil, fmt.Errorf("generating auth code url: %w", err)
	}

	return &Login{
		AuthCodeURL: authCodeURL,
		Acr:         request.acr,
		Locale:      request.locale,
		Prompt:      request.prompt,
		LoginCookie: &openid.LoginCookie{
			Acr:          request.acr,
			CodeVerifier: request.codeVerifier,
			State:        request.state,
			Nonce:        request.nonce,
			RedirectURI:  request.callbackURL,
		},
	}, nil
}

func (c *Client) newAuthorizationRequest(r *http.Request) (*authorizationRequest, error) {
	callbackURL, err := url.LoginCallback(r)
	if err != nil {
		return nil, fmt.Errorf("generating callback url: %w", err)
	}

	acr, err := getAcrParam(c, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSecurityLevel, err)
	}

	locale, err := getLocaleParam(c, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidLocale, err)
	}

	prompt, err := getPromptParam(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPrompt, err)
	}

	nonce, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("creating nonce: %w", err)
	}

	state, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("creating state: %w", err)
	}

	codeVerifier := oauth2.GenerateVerifier()

	return &authorizationRequest{
		acr:          acr,
		callbackURL:  callbackURL,
		codeVerifier: codeVerifier,
		locale:       locale,
		nonce:        nonce,
		prompt:       prompt,
		state:        state,
	}, nil
}

func (c *Client) authCodeURL(ctx context.Context, request *authorizationRequest) (string, error) {
	var authCodeURL string

	if c.cfg.Provider().PushedAuthorizationRequestEndpoint() == "" {
		opts := []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("nonce", request.nonce),
			oauth2.SetAuthURLParam("response_mode", "query"),
			oauth2.S256ChallengeOption(request.codeVerifier),
			openid.RedirectURIOption(request.callbackURL),
		}

		if resource := c.cfg.Client().ResourceIndicator(); resource != "" {
			opts = append(opts, oauth2.SetAuthURLParam("resource", resource))
		}

		if len(request.acr) > 0 {
			opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[SecurityLevelURLParameter], request.acr))
		}

		if len(request.locale) > 0 {
			opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[LocaleURLParameter], request.locale))
		}

		if len(request.prompt) > 0 {
			opts = append(opts, oauth2.SetAuthURLParam(PromptURLParameter, request.prompt))
			opts = append(opts, oauth2.SetAuthURLParam(MaxAgeURLParameter, "0"))
		}

		authCodeURL = c.oauth2Config.AuthCodeURL(request.state, opts...)
	} else {
		// TODO: implement PAR
		//  generate PAR request
		//  set all request parameters from authorizationRequest
		//  set client authentication parameters

		//  perform POST to PAR endpoint
		//  extract request_uri from response
		//  generate auth code URL with request_uri and client_id
		//  set authCodeURL
	}

	return authCodeURL, nil
}

func (l *Login) SetCookie(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter, canonicalRedirect string) error {
	l.LoginCookie.Referer = canonicalRedirect

	loginCookieJson, err := json.Marshal(l.LoginCookie)
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
