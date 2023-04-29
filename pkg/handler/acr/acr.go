package acr

import (
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
)

type Handler struct {
	Enabled       bool
	ExpectedValue string
}

func (h *Handler) Validate(sess *session.Session) error {
	if !h.Enabled || sess == nil {
		return nil
	}

	return openid.ValidateAcr(h.ExpectedValue, sess.Acr())
}

func NewHandler(cfg *config.Config) *Handler {
	return &Handler{
		Enabled:       len(cfg.OpenID.ACRValues) > 0 && cfg.AutoLogin,
		ExpectedValue: cfg.OpenID.ACRValues,
	}
}
