package middleware

import (
	"net/http"

	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

type IngressMiddleware struct {
	config openidconfig.Config
}

func Ingress(config openidconfig.Config) IngressMiddleware {
	return IngressMiddleware{config: config}
}

func (i *IngressMiddleware) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ingresses := i.config.Client().Ingresses()
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
