package middleware

import (
	"net/http"

	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func Ingress(config openidconfig.Config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ingresses := config.Client().Ingresses()
			ctx := r.Context()

			path := ingresses.MatchingPath(r)
			ctx = WithPath(ctx, path)

			matchingIngress, ok := ingresses.MatchingIngress(r)
			if ok {
				ctx = WithIngress(ctx, matchingIngress)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
