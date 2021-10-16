package router

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/request"
)

var (
	InvalidSecurityLevelError = errors.New("InvalidSecurityLevel")
	InvalidLocaleError        = errors.New("InvalidLocale")
)

func (h *Handler) LoginURL(r *http.Request, params *openid.Parameters) (string, error) {
	u, err := url.Parse(h.Provider.GetOpenIDConfiguration().AuthorizationEndpoint)
	if err != nil {
		return "", err
	}

	v := u.Query()
	v.Add("response_type", "code")
	v.Add("client_id", h.Provider.GetClientConfiguration().GetClientID())
	v.Add("redirect_uri", h.Provider.GetClientConfiguration().GetRedirectURI())
	v.Add("scope", h.Provider.GetClientConfiguration().GetScopes().String())
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
	if !h.Provider.GetClientConfiguration().GetACRValues().Enabled {
		return nil
	}

	fallback := h.Provider.GetClientConfiguration().GetACRValues().Value
	supported := h.Provider.GetOpenIDConfiguration().ACRValuesSupported

	securityLevel, err := request.LoginURLParameter(r, request.SecurityLevelURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("acr_values", securityLevel)
	return nil
}

func (h *Handler) withLocale(r *http.Request, v url.Values) error {
	if !h.Provider.GetClientConfiguration().GetUILocales().Enabled {
		return nil
	}

	fallback := h.Provider.GetClientConfiguration().GetUILocales().Value
	supported := h.Provider.GetOpenIDConfiguration().UILocalesSupported

	locale, err := request.LoginURLParameter(r, request.LocaleURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("ui_locales", locale)
	return nil
}
