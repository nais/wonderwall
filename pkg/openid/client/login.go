package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	pkgcfg "github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/strings"
	urlpkg "github.com/nais/wonderwall/pkg/url"
)

const (
	LocaleURLParameter        = "locale"
	SecurityLevelURLParameter = "level"

	ResponseModeQuery = "query"

	CodeChallengeMethodS256 = "S256"
)

var (
	ErrInvalidSecurityLevel  = errors.New("InvalidSecurityLevel")
	ErrInvalidLocale         = errors.New("InvalidLocale")
	ErrInvalidLoginParameter = errors.New("InvalidLoginParameter")

	// LoginParameterMapping maps incoming login parameters to OpenID Connect parameters
	LoginParameterMapping = map[string]string{
		LocaleURLParameter:        openid.UILocales,
		SecurityLevelURLParameter: openid.ACRValues,
	}
)

func NewLogin(c *Client, r *http.Request) (*Login, error) {
	callbackURL, err := urlpkg.LoginCallback(r)
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

	params, err := newLoginParameters(acr, callbackURL)
	if err != nil {
		return nil, fmt.Errorf("generating parameters: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(openid.Nonce, params.Nonce),
		oauth2.SetAuthURLParam(openid.ResponseMode, ResponseModeQuery),
		oauth2.SetAuthURLParam(openid.CodeChallenge, params.CodeChallenge),
		oauth2.SetAuthURLParam(openid.CodeChallengeMethod, CodeChallengeMethodS256),
		oauth2.SetAuthURLParam(openid.RedirectURI, callbackURL),
	}

	resourceIndicator := c.cfg.Client().ResourceIndicator()
	if resourceIndicator != "" {
		opts = append(opts, oauth2.SetAuthURLParam(openid.Resource, resourceIndicator))
	}

	if len(acr) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[SecurityLevelURLParameter], acr))
	}

	if len(locale) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[LocaleURLParameter], locale))
	}

	return &Login{
		authCodeURL: c.oauth2Config.AuthCodeURL(params.State, opts...),
		cookie:      params.cookie(),
		params:      params,
	}, nil
}

type Login struct {
	authCodeURL string
	cookie      *openid.LoginCookie
	params      *loginParameters
}

func (l *Login) AuthCodeURL() string {
	return l.authCodeURL
}

func (l *Login) CodeChallenge() string {
	return l.params.CodeChallenge
}

func (l *Login) CodeVerifier() string {
	return l.params.CodeVerifier
}

func (l *Login) Nonce() string {
	return l.params.Nonce
}

func (l *Login) State() string {
	return l.params.State
}

func (l *Login) SetCookie(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter, canonicalRedirect string) error {
	l.cookie.Referer = canonicalRedirect

	loginCookieJson, err := json.Marshal(l.cookie)
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

type loginParameters struct {
	Acr           string
	CodeVerifier  string
	CodeChallenge string
	Nonce         string
	RedirectURI   string
	State         string
}

func newLoginParameters(acr, redirectUri string) (*loginParameters, error) {
	codeVerifier, err := strings.GenerateBase64(64)
	if err != nil {
		return nil, fmt.Errorf("creating code verifier: %w", err)
	}

	nonce, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("creating nonce: %w", err)
	}

	state, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("creating state: %w", err)
	}

	return &loginParameters{
		Acr:           acr,
		CodeVerifier:  codeVerifier,
		CodeChallenge: CodeChallenge(codeVerifier),
		Nonce:         nonce,
		RedirectURI:   redirectUri,
		State:         state,
	}, nil
}

func (in *loginParameters) cookie() *openid.LoginCookie {
	return &openid.LoginCookie{
		Acr:          in.Acr,
		State:        in.State,
		Nonce:        in.Nonce,
		CodeVerifier: in.CodeVerifier,
		RedirectURI:  in.RedirectURI,
	}
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

	translatedAcr, ok := pkgcfg.IDPortenAcrMapping[paramValue]
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

func CodeChallenge(codeVerifier string) string {
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	codeVerifierHash := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(codeVerifierHash)
}
