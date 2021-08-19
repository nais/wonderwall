package router

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/caos/oidc/pkg/client/rp"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/go-chi/chi"
	"github.com/nais/wonderwall/pkg/config"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

const (
	idTokenKey = "id_token"
	stateParam = "state"
	nonceParam = "nonce"
	pkceCode   = "pkce"
)

type Handler struct {
	Config       config.IDPorten
	OauthConfig  oauth2.Config
	RelyingParty rp.RelyingParty
}

type loginParams struct {
	cookies      []*http.Cookie
	state        string
	codeVerifier string
	url          string
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
	v.Add("scope", "openid")
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
		codeVerifier: base64.RawURLEncoding.EncodeToString(codeVerifier),
		url:          u.String(),
	}, nil
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	params, err := h.LoginURL()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    params.state,
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "code_verifier",
		Value:    params.codeVerifier,
		Expires:  time.Now().Add(10 * time.Minute),
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

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
	jwtRequest := oidc.JWTTokenRequest{
		Issuer:    h.Config.ClientID,
		Subject:   h.Config.ClientID,
		Audience:  []string{h.Config.WellKnown.Issuer},
		ExpiresAt: oidc.Time(exp),
		IssuedAt:  oidc.Time(iat),
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

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	state, err := r.Cookie("state")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	params := r.URL.Query()
	if params.Get("error") != "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if params.Get("state") != state.Value {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	codeVerifier, err := r.Cookie("code_verifier")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	assertion, err := h.SignedJWTProfileAssertion(time.Minute * 10)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifier.Value),
		oauth2.SetAuthURLParam("client_assertion", assertion),
		oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	}

	tokens, err := h.OauthConfig.Exchange(r.Context(), params.Get("code"), opts...)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Write([]byte(tokens.AccessToken))
}

func New(handler *Handler) chi.Router {
	r := chi.NewRouter()
	r.Get("/oauth2/login", handler.Login)
	r.Get("/oauth2/callback", handler.Callback)
	return r
}
