package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/config"
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
	params, err := newLoginParameters(c)
	if err != nil {
		return nil, fmt.Errorf("generating parameters: %w", err)
	}

	callbackURL, err := urlpkg.LoginCallback(r)
	if err != nil {
		return nil, fmt.Errorf("generating callback url: %w", err)
	}

	url, err := params.authCodeURL(r, callbackURL, c.cfg.Client())
	if err != nil {
		return nil, fmt.Errorf("generating auth code url: %w", err)
	}

	loginCookie := params.cookie(callbackURL)

	return &Login{
		authCodeURL: url,
		cookie:      loginCookie,
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
	*Client
	CodeVerifier  string
	CodeChallenge string
	Nonce         string
	State         string
}

func newLoginParameters(c *Client) (*loginParameters, error) {
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
		Client:        c,
		CodeVerifier:  codeVerifier,
		CodeChallenge: CodeChallenge(codeVerifier),
		Nonce:         nonce,
		State:         state,
	}, nil
}

func (in *loginParameters) authCodeURL(r *http.Request, callbackURL string, cfg config.Client) (string, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(openid.Nonce, in.Nonce),
		oauth2.SetAuthURLParam(openid.ResponseMode, ResponseModeQuery),
		oauth2.SetAuthURLParam(openid.CodeChallenge, in.CodeChallenge),
		oauth2.SetAuthURLParam(openid.CodeChallengeMethod, CodeChallengeMethodS256),
		oauth2.SetAuthURLParam(openid.RedirectURI, callbackURL),
	}

	if cfg.ResourceIndicator() != "" {
		opts = append(opts, oauth2.SetAuthURLParam(openid.Resource, cfg.ResourceIndicator()))
	}

	opts, err := in.withSecurityLevel(r, opts)
	if err != nil {
		return "", fmt.Errorf("%w: %+v", ErrInvalidSecurityLevel, err)
	}

	opts, err = in.withLocale(r, opts)
	if err != nil {
		return "", fmt.Errorf("%w: %+v", ErrInvalidLocale, err)
	}

	authCodeUrl := in.oauth2Config.AuthCodeURL(in.State, opts...)
	return authCodeUrl, nil
}

func (in *loginParameters) cookie(redirectURI string) *openid.LoginCookie {
	return &openid.LoginCookie{
		State:        in.State,
		Nonce:        in.Nonce,
		CodeVerifier: in.CodeVerifier,
		RedirectURI:  redirectURI,
	}
}

func (in *loginParameters) withLocale(r *http.Request, opts []oauth2.AuthCodeOption) ([]oauth2.AuthCodeOption, error) {
	return withParamMapping(r,
		opts,
		LocaleURLParameter,
		in.cfg.Client().UILocales(),
		in.cfg.Provider().UILocalesSupported(),
	)
}

func (in *loginParameters) withSecurityLevel(r *http.Request, opts []oauth2.AuthCodeOption) ([]oauth2.AuthCodeOption, error) {
	return withParamMapping(r,
		opts,
		SecurityLevelURLParameter,
		in.cfg.Client().ACRValues(),
		in.cfg.Provider().ACRValuesSupported(),
	)
}

func withParamMapping(r *http.Request, opts []oauth2.AuthCodeOption, param, fallback string, supported config.Supported) ([]oauth2.AuthCodeOption, error) {
	if len(fallback) == 0 {
		return opts, nil
	}

	value, err := LoginURLParameter(r, param, fallback, supported)
	if err != nil {
		return nil, err
	}

	opts = append(opts, oauth2.SetAuthURLParam(LoginParameterMapping[param], value))
	return opts, nil
}

// LoginURLParameter attempts to get a given parameter from the given HTTP request, falling back if none found.
// The value must exist in the supplied list of supported values.
func LoginURLParameter(r *http.Request, parameter, fallback string, supported config.Supported) (string, error) {
	value := r.URL.Query().Get(parameter)

	if len(value) == 0 {
		value = fallback
	}

	if supported.Contains(value) {
		return value, nil
	}

	return value, fmt.Errorf("%w: invalid value for %s=%s", ErrInvalidLoginParameter, parameter, value)
}

func CodeChallenge(codeVerifier string) string {
	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	codeVerifierHash := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(codeVerifierHash)
}
