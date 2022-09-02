package logincallback

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	errorhandler "github.com/nais/wonderwall/pkg/handler/error"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/metrics"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	retrypkg "github.com/nais/wonderwall/pkg/retry"
	"github.com/nais/wonderwall/pkg/session"
)

type Source interface {
	GetClient() *openidclient.Client
	GetCookieOptions() cookie.Options
	GetCookieOptsPathAware(r *http.Request) cookie.Options
	GetCrypter() crypto.Crypter
	GetErrorHandler() errorhandler.Handler
	GetLoginstatus() *loginstatus.Loginstatus
	GetProvider() openidclient.OpenIDProvider
	GetSessions() *session.Handler
	GetSessionConfig() config.Session
}

func Handler(src Source, w http.ResponseWriter, r *http.Request) {
	// unconditionally clear login cookie
	clearLoginCookies(src, w, r)

	loginCookie, err := openid.GetLoginCookie(r, src.GetCrypter())
	if err != nil {
		msg := "callback: fetching login cookie"
		if errors.Is(err, http.ErrNoCookie) {
			msg += ": fallback cookie not found (user might have blocked all cookies, or the callback route was accessed before the login route)"
		}
		src.GetErrorHandler().Unauthorized(w, r, fmt.Errorf("%s: %w", msg, err))
		return
	}

	loginCallback, err := src.GetClient().LoginCallback(r, src.GetProvider(), loginCookie)
	if err != nil {
		src.GetErrorHandler().InternalError(w, r, err)
		return
	}

	if err := loginCallback.IdentityProviderError(); err != nil {
		src.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	if err := loginCallback.StateMismatchError(); err != nil {
		src.GetErrorHandler().Unauthorized(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	tokens, err := redeemValidTokens(r, loginCallback)
	if err != nil {
		src.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: redeeming tokens: %w", err))
		return
	}

	sessionLifetime := src.GetSessionConfig().MaxLifetime

	key, err := src.GetSessions().Create(r, tokens, sessionLifetime)
	if err != nil {
		src.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	opts := src.GetCookieOptsPathAware(r).
		WithExpiresIn(sessionLifetime)
	err = cookie.EncryptAndSet(w, cookie.Session, key, opts, src.GetCrypter())
	if err != nil {
		src.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: setting session cookie: %w", err))
		return
	}

	if src.GetLoginstatus().Enabled() {
		tokenResponse, err := getLoginstatusToken(src, r, tokens)
		if err != nil {
			src.GetErrorHandler().InternalError(w, r, fmt.Errorf("callback: exchanging loginstatus token: %w", err))
			return
		}

		src.GetLoginstatus().SetCookie(w, tokenResponse, src.GetCookieOptions())
		logentry.LogEntryFrom(r).Debug("callback: successfully fetched loginstatus token")
	}

	logSuccessfulLogin(r, tokens, loginCookie.Referer)
	http.Redirect(w, r, loginCookie.Referer, http.StatusTemporaryRedirect)
}

func clearLoginCookies(src Source, w http.ResponseWriter, r *http.Request) {
	opts := src.GetCookieOptsPathAware(r)
	cookie.Clear(w, cookie.Login, opts.WithSameSite(http.SameSiteNoneMode))
	cookie.Clear(w, cookie.LoginLegacy, opts.WithSameSite(http.SameSiteDefaultMode))
}

func redeemValidTokens(r *http.Request, loginCallback *openidclient.LoginCallback) (*openid.Tokens, error) {
	var tokens *openid.Tokens
	var err error

	retryable := func(ctx context.Context) error {
		tokens, err = loginCallback.RedeemTokens(ctx)
		return retry.RetryableError(err)
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return nil, err
	}

	return tokens, nil
}

func getLoginstatusToken(src Source, r *http.Request, tokens *openid.Tokens) (*loginstatus.TokenResponse, error) {
	var tokenResponse *loginstatus.TokenResponse

	retryable := func(ctx context.Context) error {
		var err error

		tokenResponse, err = src.GetLoginstatus().ExchangeToken(ctx, tokens.AccessToken)
		return retry.RetryableError(err)
	}
	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func logSuccessfulLogin(r *http.Request, tokens *openid.Tokens, referer string) {
	fields := log.Fields{
		"redirect_to": referer,
		"jti":         tokens.IDToken.GetJwtID(),
	}

	logentry.LogEntryFrom(r).WithFields(fields).Info("callback: successful login")
	metrics.ObserveLogin()
}
