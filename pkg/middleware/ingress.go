package middleware

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/ingress"
)

type IngressSource interface {
	Ingresses() *ingress.Ingresses
}

type IngressMiddleware struct {
	IngressSource
}

func Ingress(source IngressSource) IngressMiddleware {
	return IngressMiddleware{IngressSource: source}
}

func (i *IngressMiddleware) Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ingresses := i.Ingresses()
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
