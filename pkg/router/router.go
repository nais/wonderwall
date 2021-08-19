package router

import (
	"net/http"

	"github.com/caos/oidc/pkg/client/rp"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/nais/wonderwall/pkg/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	idTokenKey = "id_token"
	stateParam = "state"
	nonceParam = "nonce"
	pkceCode   = "pkce"
)

type Handler struct {
	Config       config.IDPorten
	RelyingParty rp.RelyingParty
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	opts := make([]rp.AuthURLOpt, 0)
	randomUUID, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, "failed to create state: "+err.Error(), http.StatusUnauthorized)
		return
	}
	state := randomUUID.String()

	randomUUID2, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, "failed to create nonce: "+err.Error(), http.StatusUnauthorized)
	}
	nonce := randomUUID2.String()

	if err := h.RelyingParty.CookieHandler().SetCookie(w, nonceParam, nonce); err != nil {
		http.Error(w, "failed to create nonce cookie: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if err := h.RelyingParty.CookieHandler().SetCookie(w, stateParam, state); err != nil {
		http.Error(w, "failed to create state cookie: "+err.Error(), http.StatusUnauthorized)
		return
	}

	codeVerifierPart1, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, "failed to create code verifier: "+err.Error(), http.StatusUnauthorized)
		return
	}
	codeVerifierPart2, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, "failed to create code verifier: "+err.Error(), http.StatusUnauthorized)
		return
	}
	codeVerifier := codeVerifierPart1.String() + codeVerifierPart2.String()

	if err := h.RelyingParty.CookieHandler().SetCookie(w, pkceCode, codeVerifier); err != nil {
		http.Error(w, "failed to create code challenge: "+err.Error(), http.StatusUnauthorized)
		return
	}
	codeChallenge := oidc.NewSHACodeChallenge(codeVerifier)

	opts = append(opts, rp.WithCodeChallenge(codeChallenge))
	opts = append(opts, func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("acr_values", h.Config.SecurityLevel),
			oauth2.SetAuthURLParam("ui_locales", h.Config.Locale),
			oauth2.SetAuthURLParam("response_mode", "query"),
			oauth2.SetAuthURLParam("nonce", nonce),
		}
	})

	url := rp.AuthURL(state, h.RelyingParty, opts...)

	http.Redirect(w, r, url, http.StatusFound)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
		log.Info(tokens)
	}

	rp.CodeExchangeHandler(marshalUserinfo, h.RelyingParty)(w, r)
}

func New(handler *Handler) chi.Router {
	r := chi.NewRouter()
	r.Get("/oauth2/login", handler.Login)
	r.Get("/oauth2/callback", handler.Callback)
	return r
}
