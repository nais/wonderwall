package router

import (
	"context"
	"fmt"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/nais/wonderwall/pkg/token"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

func (h *Handler) RefreshSession(ctx context.Context, session *session.Data, w http.ResponseWriter, r *http.Request) error {
	// No session nor token nor enabled = no refresh session
	if session == nil || len(session.RefreshToken) == 0 || !h.Config.RefreshToken {
		return nil
	}

	// only 1 pod can do this, unlock on any return.
	h.tokenRestore.lock.Lock()
	defer h.tokenRestore.lock.Unlock()
	sessionLifeTime, err := h.getSessionLifetime(session.AccessToken)
	if err != nil {
		return fmt.Errorf("session access_token life time: %v", err)
	}

	if !shouldRefresh(sessionLifeTime, session) {
		if session.TimesToRefresh == 0 && h.tokenRestore.ActiveSession {
			h.tokenRestore.ActiveSession = false
			h.Logout(w, r)
		}
		return nil
	}

	if err := h.ReClaimRefreshToken(ctx, session, w, r); err != nil {
		return fmt.Errorf("unable to refresh token: %v", err)
	}
	return nil
}

func shouldRefresh(sessionLifeTime time.Duration, session *session.Data) bool {
	return session.TimesToRefresh > 0 && sessionLifeTime < 10*time.Second
}

func (h *Handler) ReClaimRefreshToken(ctx context.Context, session *session.Data, w http.ResponseWriter, r *http.Request) error {
	clientAssertion, err := openid.ClientAssertion(h.Provider, time.Second*30)
	if err != nil {
		return fmt.Errorf("creating client assertion: %w", err)
	}

	h.OauthConfig.ClientSecret = clientAssertion
	src := oauth2.ReuseTokenSource(nil,
		h.OauthConfig.TokenSource(ctx, &oauth2.Token{RefreshToken: session.RefreshToken}))

	rt, err := src.Token()
	if err != nil {
		return fmt.Errorf("refresh token request: %v", err)
	}

	bin := token.NewTokenBin(rt, session.RefreshToken, session.AccessToken)

	if bin.AccessToken.Refreshed() {
		session.AccessToken = bin.AccessToken.GetRaw()
		log.Infof("refreshed access_token; next expiry %s", bin.Expiry.UTC().String())
	}

	if bin.RefreshToken.Refreshed() {
		session.RefreshToken = bin.RefreshToken.GetRaw()
		log.Infof("refreshed refresh_token")
	}

	if bin.Refreshed() {
		session.TimesToRefresh = session.TimesToRefresh - 1
		if err := h.refreshSession(ctx, session, w, r); err != nil {
			return fmt.Errorf("updating session: %v", err)
		}
	}

	return nil
}

func (h *Handler) refreshSession(ctx context.Context, session *session.Data, w http.ResponseWriter, r *http.Request) error {
	sessionLifeTime, err := h.getSessionLifetime(session.AccessToken)
	if err != nil {
		return fmt.Errorf("session (access_token) life time: %v", err)
	}

	encryptedSessionData, err := session.Encrypt(h.Crypter)
	if err != nil {
		return fmt.Errorf("encrypting session data: %w", err)
	}

	err = h.Sessions.Write(ctx, session.ExternalSessionID, encryptedSessionData, sessionLifeTime)
	if err == nil {
		h.DeleteSessionFallback(w, r)
		return nil
	}

	log.Warnf("update session: store is unavailable: %+v; using cookie fallback", err)

	err = h.SetSessionFallback(w, session, sessionLifeTime)
	if err != nil {
		return fmt.Errorf("writing session to fallback store: %w", err)
	}

	return nil
}
