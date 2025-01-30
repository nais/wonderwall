package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	stringslib "strings"

	"github.com/nais/wonderwall/internal/o11y/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/cookie"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/acr"
	"github.com/nais/wonderwall/pkg/strings"
	"github.com/nais/wonderwall/pkg/url"
)

const (
	QueryParamLocale        = "locale"
	QueryParamSecurityLevel = "level"
	QueryParamPrompt        = "prompt"
)

var QueryParamPromptAllowedValues = []string{"login", "select_account"}

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

	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("login.state", request.State))
	if request.UILocales != "" {
		span.SetAttributes(attribute.String("login.locale", request.UILocales))
	}
	if request.AcrValues != "" {
		span.SetAttributes(attribute.String("login.level", request.AcrValues))
	}
	if request.Prompt != "" {
		span.SetAttributes(attribute.String("login.prompt", request.Prompt))
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

	nonce, err := strings.GenerateBase64(32)
	if err != nil {
		return req, fmt.Errorf("creating nonce: %w", err)
	}

	state, err := strings.GenerateBase64(32)
	if err != nil {
		return req, fmt.Errorf("creating state: %w", err)
	}

	return openid.AuthorizationCodeParams{
		AcrValues:    getAcrParam(c, r),
		ClientID:     c.oauth2Config.ClientID,
		CodeVerifier: oauth2.GenerateVerifier(),
		Nonce:        nonce,
		Prompt:       getPromptParam(r),
		RedirectURI:  callbackURL,
		Resource:     c.cfg.Client().ResourceIndicator(),
		Scope:        c.oauth2Config.Scopes,
		State:        state,
		UILocales:    getLocaleParam(c, r),
	}, nil
}

func (c *Client) authCodeURL(ctx context.Context, authCodeParams openid.AuthorizationCodeParams) (string, error) {
	usePushedAuthorization := len(c.cfg.Provider().PushedAuthorizationRequestEndpoint()) > 0
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.Bool("login.pushed_authorization_request", usePushedAuthorization))

	if usePushedAuthorization {
		ctx, span := otel.StartSpan(ctx, "Client.PushedAuthorizationRequest")
		defer span.End()

		clientAuth, err := c.ClientAuthenticationParams()
		if err != nil {
			return "", fmt.Errorf("generating client authentication parameters: %w", err)
		}

		endpoint := c.cfg.Provider().PushedAuthorizationRequestEndpoint()
		body, err := c.oauthPostRequest(ctx, endpoint, authCodeParams.RequestParams().With(clientAuth))
		if err != nil {
			return "", err
		}

		var pushedAuthorizationResponse openid.PushedAuthorizationResponse
		if err := json.Unmarshal(body, &pushedAuthorizationResponse); err != nil {
			return "", fmt.Errorf("unmarshalling token response: %w", err)
		}

		return c.makeAuthCodeURL(openid.ParAuthorizationRequestParams(
			c.oauth2Config.ClientID,
			pushedAuthorizationResponse.RequestUri,
		)), nil
	}

	return c.makeAuthCodeURL(authCodeParams.RequestParams()), nil
}

func (c *Client) makeAuthCodeURL(params openid.RequestParams) string {
	var buf bytes.Buffer
	buf.WriteString(c.oauth2Config.Endpoint.AuthURL)
	if stringslib.Contains(c.oauth2Config.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(params.URLValues().Encode())
	return buf.String()
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

func (l *Login) LogFields(fields log.Fields) log.Fields {
	if acrValues := l.AcrValues; acrValues != "" {
		fields["acr"] = acrValues
	}

	if locale := l.UILocales; locale != "" {
		fields["locale"] = locale
	}

	if prompt := l.Prompt; prompt != "" {
		fields["prompt"] = prompt
	}

	return fields
}

func getAcrParam(c *Client, r *http.Request) string {
	defaultValue := c.cfg.Client().ACRValues()
	if len(defaultValue) == 0 {
		return ""
	}

	paramValue := r.URL.Query().Get(QueryParamSecurityLevel)
	if len(paramValue) == 0 {
		paramValue = defaultValue
	}

	supported := c.cfg.Provider().ACRValuesSupported()
	if supported.Contains(paramValue) {
		return paramValue
	}

	translatedAcr, ok := acr.IDPortenLegacyMapping[paramValue]
	if ok && supported.Contains(translatedAcr) {
		return translatedAcr
	}

	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("login.query.invalid_level", paramValue))
	mw.LogEntryFrom(r).Warnf("login: invalid value for %s=%s (must be one of '%s'); falling back to %q", QueryParamSecurityLevel, paramValue, supported, defaultValue)
	return defaultValue
}

func getLocaleParam(c *Client, r *http.Request) string {
	defaultValue := c.cfg.Client().UILocales()
	if len(defaultValue) == 0 {
		return ""
	}

	paramValue := r.URL.Query().Get(QueryParamLocale)
	if len(paramValue) == 0 {
		paramValue = defaultValue
	}

	supported := c.cfg.Provider().UILocalesSupported()
	if supported.Contains(paramValue) {
		return paramValue
	}

	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("login.query.invalid_locale", paramValue))
	mw.LogEntryFrom(r).Warnf("login: invalid value for %s=%s (must be one of '%s'); falling back to %q", QueryParamLocale, paramValue, supported, defaultValue)
	return defaultValue
}

func getPromptParam(r *http.Request) string {
	paramValue := r.URL.Query().Get(QueryParamPrompt)
	if len(paramValue) == 0 {
		return ""
	}

	if slices.Contains(QueryParamPromptAllowedValues, paramValue) {
		return paramValue
	}

	const defaultValue = "login"
	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("login.query.invalid_prompt", paramValue))
	mw.LogEntryFrom(r).Warnf("login: invalid value for %s=%s (must be one of '%s'); falling back to %q", QueryParamPrompt, paramValue, QueryParamPromptAllowedValues, defaultValue)
	return defaultValue
}
