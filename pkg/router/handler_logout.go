package router

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/router/request"
)

// Logout triggers self-initiated for the current user
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(h.Provider.GetOpenIDConfiguration().EndSessionEndpoint)
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

	h.deleteCookie(w, SessionCookieName, h.Cookies)

	v := u.Query()

	postLogoutURI := request.PostLogoutRedirectURI(r, h.Provider.GetClientConfiguration().GetPostLogoutRedirectURI())
	if len(postLogoutURI) > 0 {
		v.Add("post_logout_redirect_uri", postLogoutURI)
	}

	if len(idToken) > 0 {
		v.Add("id_token_hint", idToken)
	}

	u.RawQuery = v.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}
