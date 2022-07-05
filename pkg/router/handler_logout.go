package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-redis/redis/v8"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/openid"
	logentry "github.com/nais/wonderwall/pkg/router/middleware"
	"github.com/nais/wonderwall/pkg/strings"
)

// Logout triggers self-initiated for the current user
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var idToken string

	sessionData, err := h.getSessionFromCookie(w, r)
	if err == nil && sessionData != nil {
		idToken = sessionData.IDToken
		err = h.destroySession(w, r, h.localSessionID(sessionData.ExternalSessionID))
		if err != nil && !errors.Is(err, redis.Nil) {
			h.InternalError(w, r, fmt.Errorf("logout: destroying session: %w", err))
			return
		}

		fields := map[string]interface{}{
			"claims": sessionData.Claims,
		}
		logger := logentry.LogEntryWithFields(r.Context(), fields)
		logger.Info().Msg("logout: successful local logout")
	}

	cookie.Clear(w, cookie.Session, h.CookieOptions)

	if h.Config.Loginstatus.Enabled {
		h.Loginstatus.ClearCookie(w, h.CookieOptions)
	}

	u, err := url.Parse(h.OpenIDConfig.Provider().EndSessionEndpoint)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("logout: parsing end session endpoint: %w", err))
		return
	}

	logoutCookie, err := h.logoutCookie()
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("logout: generating logout cookie: %w", err))
		return
	}

	err = h.setLogoutCookie(w, logoutCookie)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("logout: setting logout cookie: %w", err))
		return
	}

	v := u.Query()
	v.Add("post_logout_redirect_uri", h.OpenIDConfig.Client().GetLogoutCallbackURI())
	v.Add("state", logoutCookie.State)

	if len(idToken) > 0 {
		v.Add("id_token_hint", idToken)
	}

	u.RawQuery = v.Encode()

	fields := map[string]interface{}{
		"redirect_to": logoutCookie.RedirectTo,
	}
	logger := logentry.LogEntryWithFields(r.Context(), fields)
	logger.Info().Msg("logout: redirecting to identity provider")

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func (h *Handler) logoutCookie() (*openid.LogoutCookie, error) {
	state, err := strings.GenerateBase64(32)
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	return &openid.LogoutCookie{
		State:      state,
		RedirectTo: h.OpenIDConfig.Client().GetPostLogoutRedirectURI(),
	}, nil
}

func (h *Handler) setLogoutCookie(w http.ResponseWriter, logoutCookie *openid.LogoutCookie) error {
	logoutCookieJson, err := json.Marshal(logoutCookie)
	if err != nil {
		return fmt.Errorf("marshalling login cookie: %w", err)
	}

	opts := h.CookieOptions.
		WithExpiresIn(LogoutCookieLifetime)
	value := string(logoutCookieJson)

	err = cookie.EncryptAndSet(w, cookie.Logout, value, opts, h.Crypter)
	if err != nil {
		return err
	}

	return nil
}
