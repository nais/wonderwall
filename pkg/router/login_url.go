package router

import (
	"errors"
	"fmt"
	"github.com/nais/wonderwall/pkg/request"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/auth"
	"github.com/nais/wonderwall/pkg/token"
)

var (
	InvalidSecurityLevelError = errors.New("InvalidSecurityLevel")
	InvalidLocaleError        = errors.New("InvalidLocale")
)

func (h *Handler) LoginURL(r *http.Request, params *auth.Parameters) (string, error) {
	u, err := url.Parse(h.Config.IDPorten.WellKnown.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}

	v := u.Query()
	v.Add("response_type", "code")
	v.Add("client_id", h.Config.IDPorten.ClientID)
	v.Add("redirect_uri", h.Config.IDPorten.RedirectURI)
	v.Add("scope", token.ScopeOpenID)
	v.Add("state", params.State)
	v.Add("nonce", params.Nonce)
	v.Add("response_mode", "query")
	v.Add("code_challenge", params.CodeChallenge)
	v.Add("code_challenge_method", "S256")

	err = h.withSecurityLevel(r, v)
	if err != nil {
		return "", fmt.Errorf("%w: %+v", InvalidSecurityLevelError, err)
	}

	err = h.withLocale(r, v)
	if err != nil {
		return "", fmt.Errorf("%w: %+v", InvalidLocaleError, err)
	}

	u.RawQuery = v.Encode()

	return u.String(), nil
}

func (h *Handler) withSecurityLevel(r *http.Request, v url.Values) error {
	if !h.Config.IDPorten.SecurityLevel.Enabled {
		return nil
	}

	fallback := h.Config.IDPorten.SecurityLevel.Value
	supported := h.Config.IDPorten.WellKnown.ACRValuesSupported

	securityLevel, err := request.LoginURLParameter(r, request.SecurityLevelURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("acr_values", securityLevel)
	return nil
}

func (h *Handler) withLocale(r *http.Request, v url.Values) error {
	if !h.Config.IDPorten.Locale.Enabled {
		return nil
	}

	fallback := h.Config.IDPorten.Locale.Value
	supported := h.Config.IDPorten.WellKnown.UILocalesSupported

	locale, err := request.LoginURLParameter(r, request.LocaleURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("ui_locales", locale)
	return nil
}
