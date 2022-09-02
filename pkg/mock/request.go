package mock

import (
	"net/http"
	"net/http/httptest"

	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
)

func NewGetRequest(target string, ingresses *ingress.Ingresses) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	match, ok := ingresses.MatchingIngress(req)
	if ok {
		req = mw.RequestWithIngress(req, match)
		req = mw.RequestWithPath(req, match.Path())
	}
	return req
}
