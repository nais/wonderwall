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
	"github.com/nais/wonderwall/pkg/openid"
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

	params := r.URL.Query()
	if params.Get("error") != "" {
		oauthError := params.Get("error")
		oauthErrorDescription := params.Get("error_description")
		h.InternalError(w, r, fmt.Errorf("callback: error from identity provider: %s: %s", oauthError, oauthErrorDescription))
		return
	}

	expectedState := loginCookie.State
	actualState := params.Get("state")
	if expectedState != actualState {
		h.Unauthorized(w, r, fmt.Errorf("callback: state parameter mismatch (possible csrf): expected %s, got %s", expectedState, actualState))
		return
	}

	rawTokens, err := h.codeExchangeForToken(r.Context(), loginCookie, params.Get("code"))
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: exchanging code: %w", err))
		return
	}

	jwkSet, err := h.Provider.GetPublicJwkSet(r.Context())
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: getting jwks: %w", err))
		return
	}

	tokens, err := jwt.ParseOauth2Token(rawTokens, *jwkSet)
	if err != nil {
		// JWKS might not be up-to-date, so we'll want to force a refresh for the next attempt
		_, _ = h.Provider.RefreshPublicJwkSet(r.Context())
		h.InternalError(w, r, fmt.Errorf("callback: parsing tokens: %w", err))
		return
	}

	err = tokens.IDToken.Validate(h.Provider, loginCookie.Nonce)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: validating id_token: %w", err))
		return
	}

	err = h.createSession(w, r, tokens, rawTokens, params)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	if h.Config.Loginstatus.Enabled {
		tokenResponse, err := h.getLoginstatusToken(r.Context(), tokens)
		if err != nil {
			h.InternalError(w, r, fmt.Errorf("callback: exchanging loginstatus token: %w", err))
			return
		}

		h.Loginstatus.SetCookie(w, tokenResponse, h.CookieOptions)
		log.Info("callback: successfully fetched loginstatus token")
	}

	logSuccessfulLogin(r, tokens, loginCookie.Referer)
	http.Redirect(w, r, loginCookie.Referer, http.StatusTemporaryRedirect)
}

func (h *Handler) codeExchangeForToken(ctx context.Context, loginCookie *openid.LoginCookie, code string) (*oauth2.Token, error) {
	var tokens *oauth2.Token
	err := retry.Do(ctx, backoff(), func(ctx context.Context) error {
		clientAssertion, err := openid.ClientAssertion(h.Provider, time.Second*30)
		if err != nil {
			return fmt.Errorf("creating client assertion: %w", err)
		}

		opts := []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("code_verifier", loginCookie.CodeVerifier),
			oauth2.SetAuthURLParam("client_assertion", clientAssertion),
			oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		}

		tokens, err = h.Client.AuthCodeGrant(ctx, code, opts)
		if err != nil {
			log.Warnf("callback: exchanging authorization code for token; retrying: %+v", err)
			return retry.RetryableError(err)
		}

		return nil
	})
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
