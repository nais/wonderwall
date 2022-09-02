package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
)

const (
	CookieLifetime = 1 * time.Hour
)

type Source interface {
	GetClient() *openidclient.Client
	GetCookieOptsPathAware(r *http.Request) cookie.Options
	GetCrypter() crypto.Crypter
	GetErrorHandler() errorhandler.Handler
}

func Handler(src Source, w http.ResponseWriter, r *http.Request) {
	login, err := src.GetClient().Login(r)
	if err != nil {
		if errors.Is(err, openidclient.InvalidSecurityLevelError) || errors.Is(err, openidclient.InvalidLocaleError) {
			src.GetErrorHandler().BadRequest(w, r, err)
		} else {
			src.GetErrorHandler().InternalError(w, r, err)
		}

		return
	}

	err = setLoginCookies(src, w, r, login.Cookie())
	if err != nil {
		src.GetErrorHandler().InternalError(w, r, fmt.Errorf("login: setting cookie: %w", err))
		return
	}

	fields := log.Fields{
		"redirect_after_login": login.CanonicalRedirect(),
	}
	logentry.LogEntryFrom(r).WithFields(fields).Debug("login: redirecting to identity provider")
	http.Redirect(w, r, login.AuthCodeURL(), http.StatusTemporaryRedirect)
}

func setLoginCookies(src Source, w http.ResponseWriter, r *http.Request, loginCookie *openid.LoginCookie) error {
	loginCookieJson, err := json.Marshal(loginCookie)
	if err != nil {
		return fmt.Errorf("marshalling login cookie: %w", err)
	}

	opts := src.GetCookieOptsPathAware(r).
		WithExpiresIn(CookieLifetime).
		WithSameSite(http.SameSiteNoneMode)
	value := string(loginCookieJson)

	err = cookie.EncryptAndSet(w, cookie.Login, value, opts, src.GetCrypter())
	if err != nil {
		return err
	}

	// set a duplicate cookie without the SameSite value set for user agents that do not properly handle SameSite
	err = cookie.EncryptAndSet(w, cookie.LoginLegacy, value, opts.WithSameSite(http.SameSiteDefaultMode), src.GetCrypter())
	if err != nil {
		return err
	}

	return nil
}
