package mock

import "github.com/go-chi/chi/v5"

func identityProviderRouter(ip *identityProviderHandler) chi.Router {
	r := chi.NewRouter()
	r.Get("/authorize", ip.Authorize)
	r.Post("/token", ip.Token)
	r.Get("/jwks", ip.Jwks)
	return r
}
