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

	v := req.URL.Query()
	v.Add("response_type", "code")
	v.Add("client_id", h.Config.ClientID)
	v.Add("redirect_uri", h.Config.RedirectURI)
	v.Add("scope", "openid")
	v.Add("state", state)
	v.Add("nonce", fmt.Sprintf("%x", nonce))
	v.Add("acr_values", "Level4") // Or Level3 - security level - fixme: config?
	v.Add("response_mode", "query")
	v.Add("ui_locales", "nb")   // optional / fixme: config?
	v.Add("code_challenge", "") // fixme
	v.Add("code_challenge_method", "S256")
	// fixme: eIDAS?
	// fixme: PAR request?
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
