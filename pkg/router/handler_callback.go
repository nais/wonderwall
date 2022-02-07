package router

import (
	"context"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/openid"
)

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	loginCookie, err := h.getLoginCookie(r)
	if err != nil {
		h.Unauthorized(w, r, fmt.Errorf("callback: fetching login cookie: %w", err))
		return
	}

	params := r.URL.Query()
	if params.Get("error") != "" {
		oauthError := params.Get("error")
		oauthErrorDescription := params.Get("error_description")
		h.InternalError(w, r, fmt.Errorf("callback: error from identity provider: %s: %s", oauthError, oauthErrorDescription))
		return
	}

	if params.Get("state") != loginCookie.State {
		h.Unauthorized(w, r, fmt.Errorf("callback: state parameter mismatch"))
		return
	}

	rawTokens, err := h.codeExchangeForToken(r.Context(), loginCookie, params.Get("code"))
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: exchanging code: %w", err))
		return
	}

	jwkSet := h.Provider.GetPublicJwkSet()

	tokens, err := jwt.ParseOauth2Token(rawTokens, *jwkSet)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: parsing tokens: %w", err))
		return
	}

	err = tokens.IDToken.Validate(h.Provider, loginCookie.Nonce)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: validating id_token: %w", err))
		return
	}

	err = h.createSession(w, r, tokens, params)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	if h.Config.Loginstatus.Enabled {
		loginstatusToken, err := h.Loginstatus.ExchangeToken(r.Context(), tokens.AccessToken)
		if err != nil {
			h.InternalError(w, r, fmt.Errorf("callback: exchanging loginstatus token: %w", err))
			return
		}

		h.Loginstatus.SetCookie(w, loginstatusToken, h.CookieOptions)
		log.Info("callback: successfully fetched loginstatus token")
	}

	h.clearLoginCookies(w)
	logSuccessfulLogin(tokens, loginCookie.Referer)
	http.Redirect(w, r, loginCookie.Referer, http.StatusTemporaryRedirect)
}

func (h *Handler) codeExchangeForToken(ctx context.Context, loginCookie *openid.LoginCookie, code string) (*oauth2.Token, error) {
	clientAssertion, err := openid.ClientAssertion(h.Provider, time.Second*30)
	if err != nil {
		return nil, fmt.Errorf("creating client assertion: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", loginCookie.CodeVerifier),
		oauth2.SetAuthURLParam("client_assertion", clientAssertion),
		oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	}

	tokens, err := h.OauthConfig.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("exchanging code for token: %w", err)
	}

	return tokens, nil
}

func logSuccessfulLogin(tokens *jwt.Tokens, referer string) {
	fields := log.Fields{
		"redirect_to": referer,
		"claims":      tokens.Claims(),
	}

	log.WithFields(fields).Info("callback: successful login")
}
