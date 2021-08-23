package router

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/nais/wonderwall/pkg/token"

	"github.com/go-chi/chi/middleware"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/auth"
	"github.com/nais/wonderwall/pkg/cryptutil"

	"github.com/go-chi/chi"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
)

const (
	SessionMaxLifetime     = time.Hour
	LoginCookieLifetime    = 10 * time.Minute
	SessionCookieName      = "io.nais.wonderwall.session"
	StateCookieName        = "io.nais.wonderwall.state"
	NonceCookieName        = "io.nais.wonderwall.nonce"
	CodeVerifierCookieName = "io.nais.wonderwall.code_verifier"
)

type Handler struct {
	Config          config.IDPorten
	OauthConfig     oauth2.Config
	Crypter         cryptutil.Crypter
	UpstreamHost    string
	IdTokenVerifier *oidc.IDTokenVerifier
	sessions        map[string]session
	lock            sync.Mutex
}

type loginParams struct {
	state        string
	codeVerifier string
	url          string
	nonce        string
}

func (h *Handler) Init() {
	h.sessions = make(map[string]session)
}

func (h *Handler) LoginURL() (*loginParams, error) {
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
	v.Add("acr_values", h.Config.SecurityLevel)
	v.Add("response_mode", "query")
	v.Add("ui_locales", h.Config.Locale)
	v.Add("code_challenge", base64.RawURLEncoding.EncodeToString(codeVerifierHash))
	v.Add("code_challenge_method", "S256")
	u.RawQuery = v.Encode()

	return &loginParams{
		state:        base64.RawURLEncoding.EncodeToString(state),
		nonce:        base64.RawURLEncoding.EncodeToString(nonce),
		codeVerifier: string(codeVerifier),
		url:          u.String(),
	}, nil
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	params, err := h.LoginURL()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = h.setEncryptedCookies(w,
		NewCookie(StateCookieName, params.state, LoginCookieLifetime),
		NewCookie(NonceCookieName, params.nonce, LoginCookieLifetime),
		NewCookie(CodeVerifierCookieName, params.codeVerifier, LoginCookieLifetime),
	)
	if err != nil {
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
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if params.Get("state") != cookies.State {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	assertion, err := h.Config.SignedJWTProfileAssertion(time.Second * 100)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
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

	idToken, err := auth.ValidateIdToken(r.Context(), h.IdTokenVerifier, tokens, cookies.Nonce)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var claims struct {
		SessionID string `json:"sid"`
	}

	if err := idToken.Claims(&claims); err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = h.setEncryptedCookie(w, SessionCookieName, claims.SessionID, SessionMaxLifetime)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.storeSession(claims.SessionID, session{
		token: tokens,
	})

	// fixme: distributed session store for multi-pod deployments

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// Proxy all requests upstream
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Duplicate the incoming request, and delete any authentication.
	upstreamRequest := r.Clone(ctx)
	upstreamRequest.Header.Del("authorization")

	session, err := h.getSessionFromCookie(r)
	if err == nil && session != nil && session.token != nil {
		// add authentication if session cookie and token checks out
		upstreamRequest.Header.Add("authorization", "Bearer "+session.token.AccessToken)
		upstreamRequest.Header.Add("x-pwned-by", "wonderwall") // todo: request id for tracing
	}

	// Request should go to correct host
	// req.Header.Set("host", req.Host)
	upstreamRequest.Host = h.UpstreamHost // fixme
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
	w.Header().Set("x-pwned-by", "wonderwall") // todo: request id for tracing
	w.WriteHeader(upstreamResponse.StatusCode)

	// Forward server's reply downstream
	io.Copy(w, upstreamResponse.Body)
}

// Logout triggers self-initiated for the current user
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	session, err := h.getSessionFromCookie(r)

	if err == nil && session != nil && session.token != nil {
		h.deleteSession(session.id)
		h.deleteCookie(w, SessionCookieName)
	}
	// todo: test logout without credentials

	u, err := url.Parse(h.Config.WellKnown.EndSessionEndpoint)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	v := u.Query()
	v.Add("post_logout_redirect_uri", h.Config.PostLogoutRedirectURI)
	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func New(handler *Handler) chi.Router {
	r := chi.NewRouter()
	r.Route("/oauth2", func(r chi.Router) {
		r.With(middleware.NoCache)
		r.Get("/login", handler.Login)
		r.Get("/callback", handler.Callback)
		r.Get("/logout", handler.Logout)
	})
	r.HandleFunc("/*", handler.Default)
	return r
}
