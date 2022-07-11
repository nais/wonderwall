package router

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/loginstatus"
	"github.com/nais/wonderwall/pkg/openid/client"
	logentry "github.com/nais/wonderwall/pkg/router/middleware"
)

const (
	retryBaseDuration = 50 * time.Millisecond
	retryMaxDuration  = 1 * time.Second
)

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	// unconditionally clear login cookie
	h.clearLoginCookies(w)

	loginCookie, err := h.getLoginCookie(r)
	if err != nil {
		msg := "callback: fetching login cookie"
		if errors.Is(err, http.ErrNoCookie) {
			msg += ": fallback cookie not found (user might have blocked all cookies, or the callback route was accessed before the login route)"
		}
		h.Unauthorized(w, r, fmt.Errorf("%s: %w", msg, err))
		return
	}

	loginCallback := h.Client.LoginCallback(r, h.Provider, loginCookie)

	if err := loginCallback.IdentityProviderError(); err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	if err := loginCallback.StateMismatchError(); err != nil {
		h.Unauthorized(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	rawTokens, err := h.exchangeAuthCode(r.Context(), loginCallback)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	tokens, err := loginCallback.ProcessTokens(r.Context(), rawTokens)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	err = h.createSession(w, r, tokens, rawTokens)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	if h.Cfg.Wonderwall().Loginstatus.Enabled {
		tokenResponse, err := h.getLoginstatusToken(r.Context(), tokens)
		if err != nil {
			h.InternalError(w, r, fmt.Errorf("callback: exchanging loginstatus token: %w", err))
			return
		}

		h.Loginstatus.SetCookie(w, tokenResponse, h.CookieOptions)
		log.Debug("callback: successfully fetched loginstatus token")
	}

	logSuccessfulLogin(r, tokens, loginCookie.Referer)
	http.Redirect(w, r, loginCookie.Referer, http.StatusTemporaryRedirect)
}

func (h *Handler) exchangeAuthCode(ctx context.Context, loginCallback client.LoginCallback) (*oauth2.Token, error) {
	var tokens *oauth2.Token
	var err error

	retryable := func(ctx context.Context) error {
		tokens, err = loginCallback.ExchangeAuthCode(ctx)
		if err != nil {
			log.Warnf("callback: retrying: %+v", err)
			return retry.RetryableError(err)
		}

		return nil
	}

	err = retry.Do(ctx, backoff(), retryable)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (h *Handler) getLoginstatusToken(ctx context.Context, tokens *jwt.Tokens) (*loginstatus.TokenResponse, error) {
	var tokenResponse *loginstatus.TokenResponse

	err := retry.Do(ctx, backoff(), func(ctx context.Context) error {
		var err error

		tokenResponse, err = h.Loginstatus.ExchangeToken(ctx, tokens.AccessToken)
		if err != nil {
			log.Warnf("callback: exchanging loginstatus token; retrying: %+v", err)
			return retry.RetryableError(err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func logSuccessfulLogin(r *http.Request, tokens *jwt.Tokens, referer string) {
	fields := map[string]interface{}{
		"redirect_to": referer,
		"claims":      tokens.Claims(),
	}

	logger := logentry.LogEntryWithFields(r.Context(), fields)
	logger.Info().Msg("callback: successful login")
}

func backoff() retry.Backoff {
	b := retry.NewFibonacci(retryBaseDuration)
	b = retry.WithMaxDuration(retryMaxDuration, b)
	return b
}
