package logoutcallback

import (
	"net/http"

	logentry "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
)

type Source interface {
	GetClient() openidclient.Client
}

func Handler(src Source, w http.ResponseWriter, r *http.Request) {
	redirect := src.GetClient().LogoutCallback(r).PostLogoutRedirectURI()

	logentry.LogEntryFrom(r).Debugf("logout/callback: redirecting to %s", redirect)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}
