package router

import (
	"errors"
	"fmt"
	"github.com/nais/wonderwall/pkg/url"
	"net/http"

	"github.com/nais/wonderwall/pkg/auth"
	"github.com/nais/wonderwall/pkg/errorhandler"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	params, err := auth.GenerateLoginParameters()
	if err != nil {
		errorhandler.InternalError(w, r, fmt.Errorf("login: generating login parameters: %w", err))
		return
	}

	loginURL, err := h.LoginURL(r, params)
	if err != nil {
		cause := fmt.Errorf("login: creating login URL: %w", err)

		if errors.Is(err, InvalidSecurityLevelError) || errors.Is(err, InvalidLocaleError) {
			errorhandler.BadRequest(w, r, cause)
		} else {
			errorhandler.InternalError(w, r, cause)
		}

		return
	}

	err = h.setLoginCookie(w, &LoginCookie{
		State:        params.State,
		Nonce:        params.Nonce,
		CodeVerifier: params.CodeVerifier,
		Referer:      url.CanonicalRedirectURL(r),
	})
	if err != nil {
		errorhandler.InternalError(w, r, fmt.Errorf("login: setting cookie: %w", err))
		return
	}

	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
}
