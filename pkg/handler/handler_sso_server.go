package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/ingress"
	"github.com/nais/wonderwall/pkg/router"
)

var _ router.Source = &SSOServerHandler{}

type SSOServerHandler struct {
}

func (s *SSOServerHandler) Login(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) Logout(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) LogoutCallback(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) LogoutFrontChannel(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) LogoutLocal(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) Session(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	//TODO implement me
	panic("implement me")
}

func (s *SSOServerHandler) GetIngresses() *ingress.Ingresses {
	//TODO implement me
	panic("implement me")
}
