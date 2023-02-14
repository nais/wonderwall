package handler

import (
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/metrics"
	mw "github.com/nais/wonderwall/pkg/middleware"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	"github.com/nais/wonderwall/pkg/session"
)

type LogoutFrontChannelSource interface {
	GetClient() *openidclient.Client
	GetCookieOptions() cookie.Options
	GetCookieOptsPathAware(r *http.Request) cookie.Options
	GetSessions() *session.Handler
}

func LogoutFrontChannel(src LogoutFrontChannelSource, w http.ResponseWriter, r *http.Request) {
	logger := mw.LogEntryFrom(r)

	// Unconditionally destroy all local references to the session.
	cookie.Clear(w, cookie.Session, src.GetCookieOptsPathAware(r))

	sessions := src.GetSessions()
	client := src.GetClient()
	key, err := getSessionKey(r, sessions, client)
	if err != nil {
		logger.Debugf("front-channel logout: getting session key: %+v; ignoring", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	err = sessions.Destroy(r, key)
	if err != nil {
		logger.Warnf("front-channel logout: destroying session: %+v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	cookie.Clear(w, cookie.Retry, src.GetCookieOptsPathAware(r))
	metrics.ObserveLogout(metrics.LogoutOperationFrontChannel)
	w.WriteHeader(http.StatusOK)
}

func getSessionKey(r *http.Request, sessions *session.Handler, client *openidclient.Client) (string, error) {
	logoutFrontchannel := client.LogoutFrontchannel(r)

	if logoutFrontchannel.MissingSidParameter() {
		ticket, err := sessions.GetTicket(r)
		if err != nil {
			return ticket.Key(), nil
		}
		return "", fmt.Errorf("neither sid parameter nor session ticket found in request: %w", err)
	}

	sid := logoutFrontchannel.Sid()
	return sessions.Key(sid), nil
}
