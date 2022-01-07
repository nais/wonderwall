package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router/request"
)

const (
	LoginCookieLifetime = 1 * time.Hour
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	params, err := openid.GenerateLoginParameters()
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

	err = h.setLoginCookies(w, &openid.LoginCookie{
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

func (h *Handler) getLoginCookie(r *http.Request) (*openid.LoginCookie, error) {
	loginCookieJson, err := h.getDecryptedCookie(r, LoginCookieName)
	if err != nil {
		requestFields := map[string]interface{}{
			"userAgent": r.UserAgent(),
		}
		log.WithField("httpRequest", requestFields).
			Warnf("failed to fetch login cookie: %+v; falling back to legacy cookie", err)
		loginCookieJson, err = h.getDecryptedCookie(r, LoginLegacyCookieName)
		if err != nil {
			return nil, err
		}
	}

	var loginCookie openid.LoginCookie
	err = json.Unmarshal([]byte(loginCookieJson), &loginCookie)
	if err != nil {
		return nil, err
	}

	return &loginCookie, nil
}

func (h *Handler) setLoginCookies(w http.ResponseWriter, loginCookie *openid.LoginCookie) error {
	loginCookieJson, err := json.Marshal(loginCookie)
	if err != nil {
		return fmt.Errorf("marshalling login cookie: %w", err)
	}

	opts := h.Cookies.
		WithExpiresIn(LoginCookieLifetime).
		WithSameSite(http.SameSiteNoneMode)
	value := string(loginCookieJson)

	err = h.setEncryptedCookie(w, LoginCookieName, value, opts)
	if err != nil {
		return err
	}

	// set a duplicate cookie without the SameSite value set for user agents that do not properly handle SameSite
	err = h.setEncryptedCookie(w, LoginLegacyCookieName, value, opts.WithSameSite(http.SameSiteDefaultMode))
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) clearLoginCookies(w http.ResponseWriter) {
	opts := h.Cookies
	cookie.Clear(w, LoginCookieName, opts.WithSameSite(http.SameSiteNoneMode))
	cookie.Clear(w, LoginLegacyCookieName, opts.WithSameSite(http.SameSiteDefaultMode))
}
