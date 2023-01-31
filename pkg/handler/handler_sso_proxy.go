package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/router"
)

var _ router.Source = &SSOProxyHandler{}

type SSOProxyHandler struct {
}

func (s *SSOProxyHandler) Login(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) Logout(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) Session(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) GetIngresses() *ingress.Ingresses {
	//TODO implement me
	panic("implement me")
}

func (s *SSOProxyHandler) GetProviderName() string {
	//TODO implement me
	panic("implement me")
}
