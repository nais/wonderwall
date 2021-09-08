package router

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/nais/wonderwall/pkg/middleware"

	"github.com/lestrrat-go/jwx/jwt"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/token"

	"github.com/go-chi/chi"
	chi_middleware "github.com/go-chi/chi/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	LoginCookieLifetime = 10 * time.Minute

	SessionCookieName      = "io.nais.wonderwall.session"
	StateCookieName        = "io.nais.wonderwall.state"
	NonceCookieName        = "io.nais.wonderwall.nonce"
	CodeVerifierCookieName = "io.nais.wonderwall.code_verifier"
	RedirectURLCookieName  = "io.nais.wonderwall.redirect_url"

	RedirectURLParameter      = "redirect"
	SecurityLevelURLParameter = "level"
	LocaleURLParameter        = "locale"
)

var (
	InvalidSecurityLevelError = errors.New("InvalidSecurityLevel")
	InvalidLocaleError        = errors.New("InvalidLocale")
)

type Handler struct {
	Config        config.IDPorten
	Crypter       cryptutil.Crypter
	OauthConfig   oauth2.Config
	SecureCookies bool
	Sessions      session.Store
	UpstreamHost  string
	jwkSet        jwk.Set
	lock          sync.Mutex
}

func NewHandler(cfg config.IDPorten, crypter cryptutil.Crypter, jwkSet jwk.Set, sessionStore session.Store, upstreamHost string) (*Handler, error) {
	oauthConfig := oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.WellKnown.AuthorizationEndpoint,
			TokenURL: cfg.WellKnown.TokenEndpoint,
		},
		RedirectURL: cfg.RedirectURI,
		Scopes:      cfg.Scopes,
	}

	return &Handler{
		Config:        cfg,
		Crypter:       crypter,
		jwkSet:        jwkSet,
		lock:          sync.Mutex{},
		OauthConfig:   oauthConfig,
		Sessions:      sessionStore,
		SecureCookies: true,
		UpstreamHost:  upstreamHost,
	}, nil
}

func (h *Handler) WithSecureCookie(enabled bool) *Handler {
	h.SecureCookies = enabled
	return h
}

// localSessionID prefixes the given `sid` with the given client ID to prevent key collisions.
// `sid` is a key that refers to the user's unique SSO session at the Identity Provider, and the same key is present
// in all tokens acquired by any Relying Party (such as Wonderwall) during that session.
// Thus, we cannot assume that the value of `sid` to uniquely identify the pair of (user, application session)
// if using a shared session store.
func (h *Handler) localSessionID(sid string) string {
	return fmt.Sprintf("%s-%s", h.Config.ClientID, sid)
}

type loginParams struct {
	state        string
	codeVerifier string
	url          string
	nonce        string
}

func (h *Handler) LoginURL(r *http.Request) (*loginParams, error) {
	codeVerifier := make([]byte, 64)
	nonce := make([]byte, 32)
	state := make([]byte, 32)

	var err error

	_, err = io.ReadFull(rand.Reader, state)
	if err != nil {
		return nil, fmt.Errorf("failed to create state: %w", err)
	}

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	_, err = io.ReadFull(rand.Reader, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to create code verifier: %w", err)
	}

	codeVerifier = []byte(base64.RawURLEncoding.EncodeToString(codeVerifier))
	hasher := sha256.New()
	hasher.Write(codeVerifier)
	codeVerifierHash := hasher.Sum(nil)

	u, err := url.Parse(h.Config.WellKnown.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	v := u.Query()
	v.Add("response_type", "code")
	v.Add("client_id", h.Config.ClientID)
	v.Add("redirect_uri", h.Config.RedirectURI)
	v.Add("scope", token.ScopeOpenID)
	v.Add("state", base64.RawURLEncoding.EncodeToString(state))
	v.Add("nonce", base64.RawURLEncoding.EncodeToString(nonce))
	v.Add("response_mode", "query")
	v.Add("code_challenge", base64.RawURLEncoding.EncodeToString(codeVerifierHash))
	v.Add("code_challenge_method", "S256")

	err = h.withSecurityLevel(r, v)
	if err != nil {
		return nil, fmt.Errorf("%w: %+v", InvalidSecurityLevelError, err)
	}

	err = h.withLocale(r, v)
	if err != nil {
		return nil, fmt.Errorf("%w: %+v", InvalidLocaleError, err)
	}

	u.RawQuery = v.Encode()

	return &loginParams{
		state:        base64.RawURLEncoding.EncodeToString(state),
		nonce:        base64.RawURLEncoding.EncodeToString(nonce),
		codeVerifier: string(codeVerifier),
		url:          u.String(),
	}, nil
}

func (h *Handler) withSecurityLevel(r *http.Request, v url.Values) error {
	if !h.Config.SecurityLevel.Enabled {
		return nil
	}

	fallback := h.Config.SecurityLevel.Value
	supported := h.Config.WellKnown.ACRValuesSupported

	securityLevel, err := LoginURLParameter(r, SecurityLevelURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("acr_values", securityLevel)
	return nil
}

func (h *Handler) withLocale(r *http.Request, v url.Values) error {
	if !h.Config.Locale.Enabled {
		return nil
	}

	fallback := h.Config.Locale.Value
	supported := h.Config.WellKnown.UILocalesSupported

	locale, err := LoginURLParameter(r, LocaleURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("ui_locales", locale)
	return nil
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	params, err := h.LoginURL(r)
	if err != nil {
		log.Errorf("login URL: %+v", err)

		status := func(err error) int {
			switch {
			case errors.Is(err, InvalidSecurityLevelError), errors.Is(err, InvalidLocaleError):
				return http.StatusBadRequest
			default:
				return http.StatusInternalServerError
			}
		}(err)

		w.WriteHeader(status)
		return
	}

	err = h.setEncryptedCookies(w,
		NewCookie(StateCookieName, params.state, LoginCookieLifetime),
		NewCookie(NonceCookieName, params.nonce, LoginCookieLifetime),
		NewCookie(CodeVerifierCookieName, params.codeVerifier, LoginCookieLifetime),
		NewCookie(RedirectURLCookieName, CanonicalRedirectURL(r), LoginCookieLifetime),
	)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, params.url, http.StatusTemporaryRedirect)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	cookies, err := h.getCallbackCookies(r)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	params := r.URL.Query()
	if params.Get("error") != "" {
		oauthError := params.Get("error")
		oauthErrorDescription := params.Get("error_description")
		log.Errorf("callback error: %s: %s", oauthError, oauthErrorDescription)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if params.Get("state") != cookies.State {
		log.Error("state parameter mismatch")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	assertion, err := h.Config.SignedJWTProfileAssertion(time.Second * 100)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", cookies.CodeVerifier),
		oauth2.SetAuthURLParam("client_assertion", assertion),
		oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	}

	tokens, err := h.OauthConfig.Exchange(r.Context(), params.Get("code"), opts...)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	idToken, err := token.ParseIDToken(r.Context(), h.jwkSet, tokens)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	validateOpts := []jwt.ValidateOption{
		jwt.WithAudience(h.Config.ClientID),
		jwt.WithClaimValue("nonce", cookies.Nonce),
		jwt.WithIssuer(h.Config.WellKnown.Issuer),
		jwt.WithAcceptableSkew(5 * time.Second),
		jwt.WithRequiredClaim("sid"),
	}

	if h.Config.SecurityLevel.Enabled {
		validateOpts = append(validateOpts, jwt.WithRequiredClaim("acr"))
	}

	err = idToken.Validate(validateOpts...)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	externalSessionID, ok := idToken.GetSID()
	if !ok {
		log.Error("missing required 'sid' claim")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sessionID := h.localSessionID(externalSessionID)

	err = h.setEncryptedCookie(w, SessionCookieName, sessionID, h.Config.SessionMaxLifetime)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = h.Sessions.Write(r.Context(), sessionID, &session.Data{
		ExternalSessionID: externalSessionID,
		OAuth2Token:       tokens,
		IDTokenSerialized: idToken.Raw,
	}, h.Config.SessionMaxLifetime)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, cookies.Referer, http.StatusTemporaryRedirect)
}

// Proxy all requests upstream
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Duplicate the incoming request, and delete any authentication.
	upstreamRequest := r.Clone(ctx)
	upstreamRequest.Header.Del("authorization")
	upstreamRequest.Header.Del("x-pwned-by")

	sess, err := h.getSessionFromCookie(r)
	if err == nil && sess != nil && sess.OAuth2Token != nil {
		// add authentication if session cookie and token checks out
		upstreamRequest.Header.Add("authorization", "Bearer "+sess.OAuth2Token.AccessToken)
		upstreamRequest.Header.Add("x-pwned-by", "wonderwall") // todo: request id for tracing
	}

	// Request should go to correct host
	upstreamRequest.Host = r.Host
	upstreamRequest.URL.Host = h.UpstreamHost
	upstreamRequest.URL.Scheme = "http"
	upstreamRequest.RequestURI = ""
	// Attach request body from original request
	upstreamRequest.Body = r.Body
	defer upstreamRequest.Body.Close()

	// Make sure requests aren't silently redirected
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	upstreamResponse, err := client.Do(upstreamRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(err.Error()))
		return
	}

	for key, values := range upstreamResponse.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(upstreamResponse.StatusCode)

	// Forward server's reply downstream
	_, err = io.Copy(w, upstreamResponse.Body)
	if err != nil {
		log.Errorf("proxy data from upstream to client: %s", err)
	}
}

// Logout triggers self-initiated for the current user
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var idToken string

	sess, err := h.getSessionFromCookie(r)
	if err == nil && sess != nil && sess.OAuth2Token != nil {
		idToken = sess.IDTokenSerialized
		err = h.Sessions.Delete(r.Context(), h.localSessionID(sess.ExternalSessionID))
		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		h.deleteCookie(w, SessionCookieName)
	}

	u, err := url.Parse(h.Config.WellKnown.EndSessionEndpoint)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	v := u.Query()
	v.Add("post_logout_redirect_uri", h.Config.PostLogoutRedirectURI)

	if len(idToken) != 0 {
		v.Add("id_token_hint", idToken)
	}

	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

// FrontChannelLogout triggers logout triggered by a third-party.
func (h *Handler) FrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	iss := params.Get("iss")
	sid := params.Get("sid")

	if len(sid) == 0 || len(iss) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sessionID := h.localSessionID(sid)

	sess, err := h.Sessions.Read(r.Context(), sessionID)
	if err != nil {
		// Can't remove session because it doesn't exist. Maybe it was garbage collected.
		// We regard this as a redundant logout and return 200 OK.
		return
	}

	// From here on, check that 'iss' from request matches data found in access token.
	tok, err := jwt.Parse([]byte(sess.OAuth2Token.AccessToken))
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = jwt.Validate(tok, jwt.WithClaimValue("iss", iss))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// All verified; delete session.
	err = h.Sessions.Delete(r.Context(), sessionID)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func New(handler *Handler, prefixes []string) chi.Router {
	r := chi.NewRouter()
	mm := middleware.PrometheusMiddleware("wonderwall")

	r.Use(mm.Handler())

	for _, prefix := range prefixes {
		r.Route(prefix+"/oauth2", func(r chi.Router) {
			r.Use(chi_middleware.NoCache)
			r.Get("/login", handler.Login)
			r.Get("/callback", handler.Callback)
			r.Get("/logout", handler.Logout)
			r.Get("/logout/frontchannel", handler.FrontChannelLogout)
		})
	}
	r.HandleFunc("/*", handler.Default)
	return r
}
