package router

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"

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

	tokens, err := h.codeExchangeForToken(r.Context(), loginCookie, params.Get("code"))
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: exchanging code: %w", err))
		return
	}

	jwkSet := h.Provider.GetPublicJwkSet()
	idToken, err := openid.ParseIDToken(*jwkSet, tokens)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: parsing id_token: %w", err))
		return
	}

	sessionID, err := h.validateIDToken(idToken, loginCookie, params)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: validating id_token: %w", err))
		return
	}

	err = h.createSession(w, r, sessionID, tokens, idToken)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	h.clearLoginCookies(w)

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

func (h *Handler) validateIDToken(idToken *openid.IDToken, loginCookie *openid.LoginCookie, params url.Values) (string, error) {
	openIDconfig := h.Provider.GetOpenIDConfiguration()
	clientConfig := h.Provider.GetClientConfiguration()

	validateOpts := []jwt.ValidateOption{
		jwt.WithAudience(clientConfig.GetClientID()),
		jwt.WithClaimValue("nonce", loginCookie.Nonce),
		jwt.WithIssuer(openIDconfig.Issuer),
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	if openIDconfig.SidClaimRequired() {
		validateOpts = append(validateOpts, jwt.WithRequiredClaim("sid"))
	}

	if len(clientConfig.GetACRValues()) > 0 {
		validateOpts = append(validateOpts, jwt.WithRequiredClaim("acr"))
	}

	err := idToken.Validate(validateOpts...)
	if err != nil {
		return "", err
	}

	sessionID, err := h.SessionId(idToken, params)
	if err != nil {
		return "", fmt.Errorf("getting external session ID from id_token: %w", err)
	}

	return sessionID, nil
}

func (h *Handler) SessionId(idToken *openid.IDToken, params url.Values) (string, error) {
	var openIDconfig = h.Provider.GetOpenIDConfiguration()
	var externalSessionID string
	var err error

	switch {
	case openIDconfig.SidClaimRequired():
		externalSessionID, err = idToken.GetStringClaim("sid")
	case openIDconfig.GetCheckSessionIframe():
		externalSessionID, err = getSessionStateFrom(params)
	default:
		externalSessionID, err = h.GenerateSessionID()
	}

	if err != nil {
		return "", err
	}

	return externalSessionID, nil
}

func getSessionStateFrom(params url.Values) (string, error) {
	var sessionStateKey = "session_state"
	sessionState := params.Get(sessionStateKey)
	if sessionState == "" {
		return "", fmt.Errorf("missing required '%s' in params", sessionStateKey)
	}
	return sessionState, nil
}

func (h *Handler) GenerateSessionID() (string, error) {
	rawID := make([]byte, 64)

	_, err := io.ReadFull(rand.Reader, rawID)
	if err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(rawID), nil
}
