package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	cfg "github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/strings"
	"github.com/nais/wonderwall/pkg/url"
)

const (
	LocaleURLParameter        = "locale"
	SecurityLevelURLParameter = "level"
)

var (
	ErrInvalidSecurityLevel  = errors.New("InvalidSecurityLevel")
	ErrInvalidLocale         = errors.New("InvalidLocale")
	ErrInvalidLoginParameter = errors.New("InvalidLoginParameter")

	// LoginParameterMapping maps incoming login parameters to OpenID Connect parameters
	LoginParameterMapping = map[string]string{
		LocaleURLParameter:        "ui_locales",
		SecurityLevelURLParameter: "acr_values",
	}
)

func NewLogin(c *Client, r *http.Request) (*Login, error) {
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

	nonce, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("creating nonce: %w", err)
	}

	state, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("creating state: %w", err)
	}

	codeVerifier := oauth2.GenerateVerifier()

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("response_mode", "query"),
		oauth2.S256ChallengeOption(codeVerifier),
		openid.RedirectURIOption(callbackURL),
	}

	if resource := c.cfg.Client().ResourceIndicator(); resource != "" {
		opts = append(opts, oauth2.SetAuthURLParam("resource", resource))
	}

	if len(acr) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[SecurityLevelURLParameter], acr))
	}

	if len(locale) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[LocaleURLParameter], locale))
	}

	return &Login{
		AuthCodeURL: c.oauth2Config.AuthCodeURL(state, opts...),
		LoginCookie: &openid.LoginCookie{
			Acr:          acr,
			CodeVerifier: codeVerifier,
			State:        state,
			Nonce:        nonce,
			RedirectURI:  callbackURL,
		},
	}, nil
}

type Login struct {
	AuthCodeURL string
	*openid.LoginCookie
}

func (l *Login) SetCookie(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter, canonicalRedirect string) error {
	l.LoginCookie.Referer = canonicalRedirect

	loginCookieJson, err := json.Marshal(l.LoginCookie)
	if err != nil {
		return fmt.Errorf("marshalling login cookie: %w", err)
	}

	value := string(loginCookieJson)

	err = cookie.EncryptAndSet(w, cookie.Login, value, opts, crypter)
	if err != nil {
		return err
	}

	// set a duplicate cookie without the SameSite value set for user agents that do not properly handle SameSite
	err = cookie.EncryptAndSet(w, cookie.LoginLegacy, value, opts.WithSameSite(http.SameSiteDefaultMode), crypter)
	if err != nil {
		return err
	}

	return nil
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

	translatedAcr, ok := cfg.IDPortenAcrMapping[paramValue]
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
