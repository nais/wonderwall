package router

import (
	"fmt"
	"github.com/nais/wonderwall/pkg/request"
	"net/http"
	"net/url"
)

// Logout triggers self-initiated for the current user
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(h.Config.IDPorten.WellKnown.EndSessionEndpoint)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("logout: parsing end session endpoint: %w", err))
		return
	}

	var idToken string

	sess, err := h.getSessionFromCookie(w, r)
	if err == nil && sess != nil {
		idToken = sess.IDToken
		err = h.destroySession(w, r, h.localSessionID(sess.ExternalSessionID))
		if err != nil {
			h.InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
			return
		}
	}

	h.deleteCookie(w, h.GetSessionCookieName())

	v := u.Query()
	v.Add("post_logout_redirect_uri", request.PostLogoutRedirectURI(r, h.Config.IDPorten.PostLogoutRedirectURI))

	if len(idToken) != 0 {
		v.Add("id_token_hint", idToken)
	}
	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}
