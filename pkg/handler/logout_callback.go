package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
)

type LogoutCallbackSource interface {
	GetClient() *openidclient.Client
	GetCookieOptsPathAware(r *http.Request) cookie.Options
}

func LogoutCallback(src LogoutCallbackSource, w http.ResponseWriter, r *http.Request) {
	redirect := src.GetClient().LogoutCallback(r).PostLogoutRedirectURI()

	cookie.Clear(w, cookie.Retry, src.GetCookieOptsPathAware(r))
	logentry.LogEntryFrom(r).Debugf("logout/callback: redirecting to %s", redirect)
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}
