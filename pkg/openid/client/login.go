package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	stringslib "strings"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/internal/retry"
	"github.com/nais/wonderwall/pkg/cookie"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/acr"
	"github.com/nais/wonderwall/pkg/strings"
	"github.com/nais/wonderwall/pkg/url"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
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
		resp, err := retry.DoValue(ctx, func(ctx context.Context) (*openid.PushedAuthorizationResponse, error) {
			body, err := c.oauthPostRequest(ctx, endpoint, authCodeParams.RequestParams().With(clientAuth))
			if err != nil {
				if errors.Is(err, ErrOpenIDServer) {
					return nil, retry.RetryableError(err)
				}
				return nil, err
			}

			var pushedAuthorizationResponse openid.PushedAuthorizationResponse
			if err := json.Unmarshal(body, &pushedAuthorizationResponse); err != nil {
				return nil, fmt.Errorf("unmarshalling token response: %w", err)
			}

			return &pushedAuthorizationResponse, nil
		})
		if err != nil {
			return "", fmt.Errorf("requesting pushed authorization: %w", err)
		}

		return c.makeAuthCodeURL(openid.ParAuthorizationRequestParams(
			c.oauth2Config.ClientID,
			resp.RequestUri,
		)), nil
	}

	return c.makeAuthCodeURL(authCodeParams.RequestParams()), nil
}

func (c *Client) makeAuthCodeURL(params openid.RequestParams) string {
	var sb stringslib.Builder
	sb.WriteString(c.oauth2Config.Endpoint.AuthURL)
	if stringslib.Contains(c.oauth2Config.Endpoint.AuthURL, "?") {
		sb.WriteByte('&')
	} else {
		sb.WriteByte('?')
	}
	sb.WriteString(params.URLValues().Encode())
	return sb.String()
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
	supported := c.cfg.Provider().ACRValuesSupported()
	param := r.URL.Query().Get(QueryParamSecurityLevel)
	if param != "" {
		if supported.Contains(param) {
			return param
		}
		translated, ok := acr.IDPortenLegacyMapping[param]
		if ok && supported.Contains(translated) {
			return translated
		}

		span := trace.SpanFromContext(r.Context())
		span.SetAttributes(attribute.String("login.query.invalid_level", param))
		// The provided ACR value is empty or invalid, check if we can fall back to a default value
	}

	defaultAcr := c.cfg.Client().ACRValues()
	if defaultAcr == "" {
		return ""
	}
	if !supported.Contains(defaultAcr) {
		translated, ok := acr.IDPortenLegacyMapping[defaultAcr]
		if ok && supported.Contains(translated) {
			defaultAcr = translated
		} else {
			// The default ACR value is invalid
			return ""
		}
	}
	if param != "" {
		mw.LogEntryFrom(r).Warnf("login: invalid value for %s=%s (must be one of '%s'); falling back to %q", QueryParamSecurityLevel, param, supported, defaultAcr)
	}
	return defaultAcr
}

func getLocaleParam(c *Client, r *http.Request) string {
	supported := c.cfg.Provider().UILocalesSupported()
	param := r.URL.Query().Get(QueryParamLocale)
	if param != "" {
		if supported.Contains(param) {
			return param
		}

		span := trace.SpanFromContext(r.Context())
		span.SetAttributes(attribute.String("login.query.invalid_locale", param))
		// The provided locale is invalid, check if we can fall back to a default value
	}

	defaultLocale := c.cfg.Client().UILocales()
	if defaultLocale == "" || !supported.Contains(defaultLocale) {
		// The default locale is empty or invalid
		return ""
	}
	if param != "" {
		mw.LogEntryFrom(r).Warnf("login: invalid value for %s=%s (must be one of '%s'); falling back to %q", QueryParamLocale, param, supported, defaultLocale)
	}
	return defaultLocale
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
