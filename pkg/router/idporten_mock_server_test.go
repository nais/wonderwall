package router_test

import (
	"encoding/json"
	"github.com/go-chi/chi"
	"net/http"
)

type idporten struct {
}

type TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func (ip *idporten) Authorize(w http.ResponseWriter, r *http.Request) {
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

func idportenRouter(ip *idporten) chi.Router {
	r := chi.NewRouter()
	r.Post("/authorize", ip.Authorize)
	return r
}
