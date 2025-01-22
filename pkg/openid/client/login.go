package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	authorizationRequest
	Cookie *openid.LoginCookie
}

type authorizationRequest struct {
	Acr          string
	CallbackURL  string
	CodeVerifier string
	Locale       string
	Nonce        string
	Prompt       string
	State        string
}

func (c *Client) Login(r *http.Request) (*Login, error) {
	request, err := c.newAuthorizationRequest(r)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	authCodeURL, err := c.authCodeURL(r.Context(), request)
	if err != nil {
		return nil, fmt.Errorf("login: generating auth code url: %w", err)
	}

	return &Login{
		AuthCodeURL:          authCodeURL,
		authorizationRequest: *request,
		Cookie: &openid.LoginCookie{
			Acr:          request.Acr,
			CodeVerifier: request.CodeVerifier,
			State:        request.State,
			Nonce:        request.Nonce,
			RedirectURI:  request.CallbackURL,
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
		Acr:          acr,
		CallbackURL:  callbackURL,
		CodeVerifier: codeVerifier,
		Locale:       locale,
		Nonce:        nonce,
		Prompt:       prompt,
		State:        state,
	}, nil
}

func (c *Client) authCodeURL(ctx context.Context, request *authorizationRequest) (string, error) {
	var authCodeURL string

	if c.cfg.Provider().PushedAuthorizationRequestEndpoint() == "" {
		opts := []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("nonce", request.Nonce),
			oauth2.SetAuthURLParam("response_mode", "query"),
			oauth2.S256ChallengeOption(request.CodeVerifier),
			openid.RedirectURIOption(request.CallbackURL),
		}

		if resource := c.cfg.Client().ResourceIndicator(); resource != "" {
			opts = append(opts, oauth2.SetAuthURLParam("resource", resource))
		}

		if len(request.Acr) > 0 {
			opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[SecurityLevelURLParameter], request.Acr))
		}

		if len(request.Locale) > 0 {
			opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[LocaleURLParameter], request.Locale))
		}

		if len(request.Prompt) > 0 {
			opts = append(opts, oauth2.SetAuthURLParam(PromptURLParameter, request.Prompt))
			opts = append(opts, oauth2.SetAuthURLParam(MaxAgeURLParameter, "0"))
		}

		authCodeURL = c.oauth2Config.AuthCodeURL(request.State, opts...)
	} else {
		params := map[string]string{
			"client_id":             c.oauth2Config.ClientID,
			"code_challenge":        oauth2.S256ChallengeFromVerifier(request.CodeVerifier),
			"code_challenge_method": "S256",
			"nonce":                 request.Nonce,
			"redirect_uri":          request.CallbackURL,
			"response_mode":         "query",
			"response_type":         "code",
			"scope":                 stringslib.Join(c.oauth2Config.Scopes, " "),
			"state":                 request.State,
		}

		if resource := c.cfg.Client().ResourceIndicator(); resource != "" {
			params["resource"] = resource
		}

		if len(request.Acr) > 0 {
			params[LoginParameterMapping[SecurityLevelURLParameter]] = request.Acr
		}

		if len(request.Locale) > 0 {
			params[LoginParameterMapping[LocaleURLParameter]] = request.Locale
		}

		if len(request.Prompt) > 0 {
			params[PromptURLParameter] = request.Prompt
			params[MaxAgeURLParameter] = "0"
		}

		authParams, err := c.AuthParams()
		if err != nil {
			return "", fmt.Errorf("generating client authentication parameters: %w", err)
		}

		urlValues := authParams.URLValues(params)

		requestBody := stringslib.NewReader(urlValues.Encode())

		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Provider().PushedAuthorizationRequestEndpoint(), requestBody)
		if err != nil {
			return "", fmt.Errorf("creating request: %w", err)
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.httpClient.Do(r)
		if err != nil {
			return "", fmt.Errorf("performing request: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("reading server response: %w", err)
		}

		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			var errorResponse openid.TokenErrorResponse
			if err := json.Unmarshal(body, &errorResponse); err != nil {
				return "", fmt.Errorf("%w: HTTP %d: unmarshalling error response: %+v", ErrOpenIDClient, resp.StatusCode, err)
			}
			return "", fmt.Errorf("%w: HTTP %d: %s: %s", ErrOpenIDClient, resp.StatusCode, errorResponse.Error, errorResponse.ErrorDescription)
		} else if resp.StatusCode >= 500 {
			return "", fmt.Errorf("%w: HTTP %d: %s", ErrOpenIDServer, resp.StatusCode, body)
		}

		var pushedAuthorizationResponse openid.PushedAuthorizationResponse
		if err := json.Unmarshal(body, &pushedAuthorizationResponse); err != nil {
			return "", fmt.Errorf("unmarshalling token response: %w", err)
		}

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
