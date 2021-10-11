package router

import (
	"fmt"
	"github.com/nais/wonderwall/pkg/auth"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/token"
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
		h.Unauthorized(w, r, fmt.Errorf("callback: error from identity provider: %s: %s", oauthError, oauthErrorDescription))
		return
	}

	if params.Get("state") != loginCookie.State {
		h.Unauthorized(w, r, fmt.Errorf("callback: state parameter mismatch"))
		return
	}

	assertion, err := auth.ClientAssertion(h.Config.IDPorten, time.Second * 30)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: creating client assertion: %w", err))
		return
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", loginCookie.CodeVerifier),
		oauth2.SetAuthURLParam("client_assertion", assertion),
		oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
	}

	tokens, err := h.OauthConfig.Exchange(r.Context(), params.Get("code"), opts...)
	if err != nil {
		h.Unauthorized(w, r, fmt.Errorf("callback: exchanging code: %w", err))
		return
	}

	idToken, err := token.ParseIDToken(h.jwkSet, tokens)
	if err != nil {
		h.Unauthorized(w, r, fmt.Errorf("callback: parsing id_token: %w", err))
		return
	}

	validateOpts := []jwt.ValidateOption{
		jwt.WithAudience(h.Config.IDPorten.ClientID),
		jwt.WithClaimValue("nonce", loginCookie.Nonce),
		jwt.WithIssuer(h.Config.IDPorten.WellKnown.Issuer),
		jwt.WithAcceptableSkew(5 * time.Second),
		jwt.WithRequiredClaim("sid"),
	}

	if h.Config.IDPorten.SecurityLevel.Enabled {
		validateOpts = append(validateOpts, jwt.WithRequiredClaim("acr"))
	}

	err = idToken.Validate(validateOpts...)
	if err != nil {
		h.Unauthorized(w, r, fmt.Errorf("callback: validating id_token: %w", err))
		return
	}

	externalSessionID, ok := idToken.GetSID()
	if !ok {
		h.Unauthorized(w, r, fmt.Errorf("callback: missing required 'sid' claim in id_token"))
		return
	}

	err = h.createSession(w, r, externalSessionID, tokens, idToken)
	if err != nil {
		h.InternalError(w, r, fmt.Errorf("callback: creating session: %w", err))
		return
	}

	// delete login cookie as we no longer need it
	h.deleteCookie(w, h.GetLoginCookieName())

	http.Redirect(w, r, loginCookie.Referer, http.StatusTemporaryRedirect)
}
