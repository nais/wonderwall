package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/loginstatus"
	logentry "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/openid/client"
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

	loginCallback, err := h.Client.LoginCallback(r, h.Provider, loginCookie)
	if err != nil {
		h.InternalError(w, r, err)
		return
	}

	if err := loginCallback.IdentityProviderError(); err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	if err := loginCallback.StateMismatchError(); err != nil {
		h.Unauthorized(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	tokens, err := h.redeemValidTokens(r.Context(), loginCallback)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: %w", err))
		return
	}

	err = h.createSession(w, r, tokens)
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

func (h *Handler) redeemValidTokens(ctx context.Context, loginCallback client.LoginCallback) (*openid.Tokens, error) {
	var tokens *openid.Tokens
	var err error

	retryable := func(ctx context.Context) error {
		tokens, err = loginCallback.RedeemTokens(ctx)
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

func (h *Handler) getLoginstatusToken(ctx context.Context, tokens *openid.Tokens) (*loginstatus.TokenResponse, error) {
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

func logSuccessfulLogin(r *http.Request, tokens *openid.Tokens, referer string) {
	fields := map[string]interface{}{
		"redirect_to": referer,
		"jti":         tokens.IDToken.GetJwtID(),
	}

	logger := logentry.LogEntryWithFields(r.Context(), fields)
	logger.Info().Msg("callback: successful login")
}

func backoff() retry.Backoff {
	b := retry.NewFibonacci(retryBaseDuration)
	b = retry.WithMaxDuration(retryMaxDuration, b)
	return b
}