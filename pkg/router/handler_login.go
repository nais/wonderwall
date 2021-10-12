package router

import (
	"errors"
	"fmt"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/request"
	"net/http"

	"github.com/nais/wonderwall/pkg/auth"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	params, err := auth.GenerateLoginParameters()
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("login: generating login parameters: %w", err))
		return
	}

	loginURL, err := h.LoginURL(r, params)
	if err != nil {
		cause := fmt.Errorf("login: creating login URL: %w", err)

		if errors.Is(err, InvalidSecurityLevelError) || errors.Is(err, InvalidLocaleError) {
			h.BadRequest(w, r, cause)
		} else {
			h.InternalError(w, r, cause)
		}

		return
	}

	err = h.setLoginCookie(w, &cookie.Login{
		State:        params.State,
		Nonce:        params.Nonce,
		CodeVerifier: params.CodeVerifier,
		Referer:      request.CanonicalRedirectURL(r),
	})
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("login: setting cookie: %w", err))
		return
	}

	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
}