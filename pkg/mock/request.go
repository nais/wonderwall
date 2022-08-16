package mock

import (
	"net/http"
	"net/http/httptest"

	mw "github.com/nais/wonderwall/pkg/middleware"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func NewGetRequest(target string, openidConfig openidconfig.Config) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	match, ok := openidConfig.Client().Ingresses().MatchingIngress(req)
	if ok {
		req = mw.RequestWithIngress(req, match)
		req = mw.RequestWithPath(req, match.Path())
	}
	return req
}
