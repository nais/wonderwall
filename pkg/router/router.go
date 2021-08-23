package router

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

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
	ScopeOpenID            = "openid"
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
	sessions        map[string]*oauth2.Token
	lock            sync.Mutex
}

type loginParams struct {
	state        string
	codeVerifier string
	url          string
	nonce        string
}

func (h *Handler) Init() {
	h.sessions = make(map[string]*oauth2.Token)
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
	v.Add("scope", ScopeOpenID)
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

	err = h.setEncryptedCookie(w, StateCookieName, params.state, LoginCookieLifetime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = h.setEncryptedCookie(w, NonceCookieName, params.nonce, LoginCookieLifetime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = h.setEncryptedCookie(w, CodeVerifierCookieName, params.codeVerifier, LoginCookieLifetime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, params.url, http.StatusTemporaryRedirect)
}

func (h *Handler) SignedJWTProfileAssertion(expiration time.Duration) (string, error) {
	key := &jose.JSONWebKey{}
	err := json.Unmarshal([]byte(h.Config.ClientJWK), key)
	if err != nil {
		return "", err
	}
	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}
	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}

	iat := time.Now()
	exp := iat.Add(expiration)
	jwtRequest := &JWTTokenRequest{
		Issuer:    h.Config.ClientID,
		Subject:   h.Config.ClientID,
		Audience:  h.Config.WellKnown.Issuer,
		Scopes:    ScopeOpenID,
		ExpiresAt: exp.Unix(),
		IssuedAt:  iat.Unix(),
	}

	payload, err := json.Marshal(jwtRequest)
	if err != nil {
		return "", err
	}

	result, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return result.CompactSerialize()
}

func (h *Handler) setEncryptedCookie(w http.ResponseWriter, key string, plaintext string, expiresIn time.Duration) error {
	ciphertext, err := h.Crypter.Encrypt([]byte(plaintext))
	if err != nil {
		return fmt.Errorf("unable to encrypt cookie '%s': %w", key, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     key,
		Value:    base64.StdEncoding.EncodeToString(ciphertext),
		Expires:  time.Now().Add(expiresIn),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (h *Handler) getEncryptedCookie(r *http.Request, key string) (string, error) {
	encoded, err := r.Cookie(key)
	if err != nil {
		return "", fmt.Errorf("no cookie named '%s': %w", key, err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded.Value)
	if err != nil {
		return "", fmt.Errorf("cookie named '%s' is not base64 encoded: %w", key, err)
	}

	plaintext, err := h.Crypter.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt cookie '%s': %w", key, err)
	}

	return string(plaintext), nil
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	state, err := h.getEncryptedCookie(r, StateCookieName)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	nonce, err := h.getEncryptedCookie(r, NonceCookieName)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	codeVerifier, err := h.getEncryptedCookie(r, CodeVerifierCookieName)
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

	if params.Get("state") != state {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	assertion, err := h.SignedJWTProfileAssertion(time.Second * 100)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
		oauth2.SetAuthURLParam("client_assertion", assertion),
		oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	}

	token, err := h.OauthConfig.Exchange(r.Context(), params.Get("code"), opts...)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	idToken, err := auth.ValidateIdToken(r.Context(), h.IdTokenVerifier, token, nonce)
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

	h.storeSession(claims.SessionID, token)

	// fixme: distributed session store for multi-pod deployments

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (h *Handler) storeSession(key string, token *oauth2.Token) {
	h.lock.Lock()
	h.sessions[key] = token
	h.lock.Unlock()
}

func (h *Handler) deleteSession(key string) {
	h.lock.Lock()
	delete(h.sessions, key)
	h.lock.Unlock()
}

// Proxy all requests upstream
func (h *Handler) Default(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	upstreamRequest := r.Clone(ctx)

	upstreamRequest.Header.Del("authorization")

	// fixme: let upstream application decide what to do with unauthenticated clients
	// Get credentials from session cache
	sessionID, err := h.getEncryptedCookie(r, SessionCookieName)
	if err != nil {
		log.Tracef("no session cookie; should redirect to /oauth2/login")
		http.Redirect(w, r, "/oauth2/login", http.StatusTemporaryRedirect)
		return
	}
	token, ok := h.sessions[sessionID]
	if !ok {
		log.Tracef("no token stored for session %s; needs garbage collection client side", sessionID)
		http.Redirect(w, r, "/oauth2/login", http.StatusTemporaryRedirect)
		return
	}

	// Duplicate the incoming request, and add authentication.
	upstreamRequest.Header.Add("authorization", "Bearer "+token.AccessToken)
	upstreamRequest.Header.Add("x-pwned-by", "wonderwall") // todo: request id for tracing
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
	sessionID, err := h.getEncryptedCookie(r, SessionCookieName)
	if err != nil {
		log.Tracef("no session cookie; should redirect to /oauth2/login")
		http.Redirect(w, r, "/oauth2/login", http.StatusTemporaryRedirect)
		return
	}

	_, ok := h.sessions[sessionID]
	if !ok {
		log.Tracef("no token stored for session %s; needs garbage collection client side", sessionID)
		http.Redirect(w, r, "/oauth2/login", http.StatusTemporaryRedirect)
		return
	}

	h.deleteSession(sessionID)

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

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
	r.With(middleware.DefaultLogger)
	r.Get("/oauth2/login", handler.Login)
	r.Get("/oauth2/callback", handler.Callback)
	r.Get("/oauth2/logout_self", handler.Logout)
	r.HandleFunc("/*", handler.Default)
	return r
}
