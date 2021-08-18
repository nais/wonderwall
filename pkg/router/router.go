package router

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/nais/wonderwall/pkg/config"
)

type Handler struct {
	Config config.IDPorten
}

func (h *Handler) LoginURL() (string, error) {
	state := "foo" // FIXME: cookie
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("GET", h.Config.WellKnown.AuthorizationEndpoint, nil)
	if err != nil {
		return "", err
	}

	// https://docs.digdir.no/oidc_protocol_authorize.html
	// sidecar:
	//   locale: nb          # enum i well-known
	//   acr_values: Level4  # enum i well-known
	v := req.URL.Query()
	v.Add("response_type", "code")
	v.Add("client_id", h.Config.ClientID)
	v.Add("redirect_uri", h.Config.RedirectURI)
	v.Add("scope", "openid")
	v.Add("state", state)
	v.Add("nonce", fmt.Sprintf("%x", nonce))
	v.Add("acr_values", h.Config.SecurityLevel)
	v.Add("response_mode", "query")
	v.Add("ui_locales", h.Config.Locale)
	v.Add("code_challenge", "") // fixme
	v.Add("code_challenge_method", "S256")
	req.URL.RawQuery = v.Encode()

	return req.URL.String(), nil
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	uri, err := h.LoginURL()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", uri)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {

}

func New(handler *Handler) chi.Router {
	r := chi.NewRouter()
	r.Get("/oauth2/login", handler.Login)
	r.Get("/oauth2/callback", handler.Callback)
	return r
}
