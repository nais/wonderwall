package router_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/lestrrat-go/jwx/jwk"
)

type IDPorten struct {
	Clients  map[string]string
	Codes    map[string]AuthRequest
	Keys     jwk.Set
	Sessions map[string]string
}

type AuthRequest struct {
	AcrLevel      string
	CodeChallenge string
	Locale        string
	Nonce         string
}

func NewIDPorten(clients map[string]string) *IDPorten {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	key, err := jwk.New(privateKey)
	if err != nil {
		panic(err)
	}

	keys := jwk.NewSet()
	keys.Add(key)

	return &IDPorten{
		Clients:  clients,
		Sessions: make(map[string]string),
		Codes:    make(map[string]AuthRequest),
		Keys:     keys,
	}
}

type TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func (ip *IDPorten) Authorize(w http.ResponseWriter, r *http.Request) {
	// fixme: generate valid access token and id token; sign them with the correct key
	token := &TokenJSON{
		AccessToken:  "access-token",
		TokenType:    "token-type",
		RefreshToken: "refresh-token",
		IDToken:      "id-token",
		ExpiresIn:    1200,
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
}

func (ip *IDPorten) Token(w http.ResponseWriter, r *http.Request) {

}

func (ip *IDPorten) EndSession(w http.ResponseWriter, r *http.Request) {

}

func (ip *IDPorten) Jwks(w http.ResponseWriter, r *http.Request) {

}

func (ip *IDPorten) WellKnown(w http.ResponseWriter, r *http.Request) {

}

func idportenRouter(ip *IDPorten) chi.Router {
	r := chi.NewRouter()
	r.Post("/authorize", ip.Authorize)
	r.Get("/token", ip.Token)
	r.Get("/endsession", ip.EndSession)
	r.Get("/jwks", ip.Jwks)
	r.Get("/.well-known/openid-configuration", ip.WellKnown)
	return r
}
