package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/nais/wonderwall/pkg/auth"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/errorhandler"
	"github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/token"

	"github.com/go-chi/chi"
	chi_middleware "github.com/go-chi/chi/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	RedirectURLParameter           = "redirect"
	SecurityLevelURLParameter      = "level"
	LocaleURLParameter             = "locale"
	PostLogoutRedirectURIParameter = "post_logout_redirect_uri"
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

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	params, err := auth.GenerateLoginParameters()
	if err != nil {
		errorhandler.InternalError(w, fmt.Errorf("login: generating login parameters: %w", err))
		return
	}

	loginURL, err := h.LoginURL(r, params)
	if err != nil {
		cause := fmt.Errorf("login: creating login URL: %w", err)

		if errors.Is(err, errorhandler.InvalidSecurityLevelError) || errors.Is(err, errorhandler.InvalidLocaleError) {
			errorhandler.BadRequest(w, cause)
		} else {
			errorhandler.InternalError(w, cause)
		}

		return
	}

	err = h.setLoginCookie(w, &LoginCookie{
		State:        params.State,
		Nonce:        params.Nonce,
		CodeVerifier: params.CodeVerifier,
		Referer:      CanonicalRedirectURL(r),
	})
	if err != nil {
		errorhandler.InternalError(w, fmt.Errorf("login: setting cookie: %w", err))
		return
	}

	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	loginCookie, err := h.getLoginCookie(w, r)
	if err != nil {
		errorhandler.Unauthorized(w, fmt.Errorf("callback: fetching login cookie: %w", err))
		return
	}

	params := r.URL.Query()
	if params.Get("error") != "" {
		oauthError := params.Get("error")
		oauthErrorDescription := params.Get("error_description")
		errorhandler.Unauthorized(w, fmt.Errorf("callback: error from identity provider: %s: %s", oauthError, oauthErrorDescription))
		return
	}

	if params.Get("state") != loginCookie.State {
		errorhandler.Unauthorized(w, fmt.Errorf("callback: state parameter mismatch"))
		return
	}

	assertion, err := h.Config.SignedJWTProfileAssertion(time.Second * 100)
	if err != nil {
		errorhandler.InternalError(w, fmt.Errorf("callback: creating client assertion: %w", err))
		return
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", loginCookie.CodeVerifier),
		oauth2.SetAuthURLParam("client_assertion", assertion),
		oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	}

	tokens, err := h.OauthConfig.Exchange(r.Context(), params.Get("code"), opts...)
	if err != nil {
		errorhandler.Unauthorized(w, fmt.Errorf("callback: exchanging code: %w", err))
		return
	}

	idToken, err := token.ParseIDToken(h.jwkSet, tokens)
	if err != nil {
		errorhandler.Unauthorized(w, fmt.Errorf("callback: parsing id_token: %w", err))
		return
	}

	validateOpts := []jwt.ValidateOption{
		jwt.WithAudience(h.Config.ClientID),
		jwt.WithClaimValue("nonce", loginCookie.Nonce),
		jwt.WithIssuer(h.Config.WellKnown.Issuer),
		jwt.WithAcceptableSkew(5 * time.Second),
		jwt.WithRequiredClaim("sid"),
	}

	if h.Config.SecurityLevel.Enabled {
		validateOpts = append(validateOpts, jwt.WithRequiredClaim("acr"))
	}

	err = idToken.Validate(validateOpts...)
	if err != nil {
		errorhandler.Unauthorized(w, fmt.Errorf("callback: validating id_token: %w", err))
		return
	}

	externalSessionID, ok := idToken.GetSID()
	if !ok {
		errorhandler.Unauthorized(w, fmt.Errorf("callback: missing required 'sid' claim in id_token"))
		return
	}

	err = h.createSession(w, r, externalSessionID, tokens, idToken)
	if err != nil {
		errorhandler.InternalError(w, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	http.Redirect(w, r, loginCookie.Referer, http.StatusTemporaryRedirect)
}

// Default proxies all requests upstream
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Duplicate the incoming request, and delete any authentication.
	upstreamRequest := r.Clone(ctx)
	upstreamRequest.Header.Del("authorization")
	upstreamRequest.Header.Del("x-pwned-by")

	sess, err := h.getSessionFromCookie(r)
	if err == nil && sess != nil && len(sess.AccessToken) > 0 {
		// add authentication if session cookie and token checks out
		upstreamRequest.Header.Add("authorization", "Bearer "+sess.AccessToken)
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
	u, err := url.Parse(h.Config.WellKnown.EndSessionEndpoint)
	if err != nil {
		errorhandler.InternalError(w, fmt.Errorf("logout: parsing end session endpoint: %w", err))
		return
	}

	var idToken string

	sess, err := h.getSessionFromCookie(r)
	if err == nil && sess != nil {
		idToken = sess.IDToken
		err = h.destroySession(w, r, h.localSessionID(sess.ExternalSessionID))
		if err != nil {
			errorhandler.InternalError(w, fmt.Errorf("logout: destroying session: %w", err))
			return
		}
	}

	h.deleteCookie(w, h.GetSessionCookieName())

	v := u.Query()
	v.Add("post_logout_redirect_uri", PostLogoutRedirectURI(r, h.Config.PostLogoutRedirectURI))

	if len(idToken) != 0 {
		v.Add("id_token_hint", idToken)
	}
	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

// FrontChannelLogout triggers logout triggered by a third-party.
func (h *Handler) FrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	sid := params.Get("sid")

	if len(sid) == 0 {
		errorhandler.BadRequest(w, fmt.Errorf("front-channel logout: sid not set in query parameter"))
		return
	}

	sessionID := h.localSessionID(sid)

	err := h.destroySession(w, r, sessionID)
	if err != nil {
		log.Error(err)
		// Session is already destroyed at the OP and is highly unlikely to be used again.
	}

	// Unconditionally destroy all local references to the session.
	h.deleteCookie(w, h.GetSessionCookieName())
}

func New(handler *Handler, prefixes []string) chi.Router {
	r := chi.NewRouter()
	mm := middleware.PrometheusMiddleware("wonderwall")

	for _, prefix := range prefixes {
		r.Route(prefix+"/oauth2", func(r chi.Router) {
			r.Use(mm.Handler())
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
