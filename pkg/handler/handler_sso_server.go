package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/router"
)

var _ router.Source = &SSOServerHandler{}

type SSOServerHandler struct {
	DefaultHandler
}

func NewSSOServerHandler(handler *DefaultHandler) *SSOServerHandler {
	return &SSOServerHandler{DefaultHandler: *handler}
}

func (s *SSOServerHandler) ReverseProxy(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
