package router

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/openid"
	request2 "github.com/nais/wonderwall/pkg/router/request"
)

var (
	InvalidSecurityLevelError = errors.New("InvalidSecurityLevel")
	InvalidLocaleError        = errors.New("InvalidLocale")
)

func (h *Handler) LoginURL(r *http.Request, params *openid.LoginParameters) (string, error) {
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
	acrValues := h.Provider.GetClientConfiguration().GetACRValues()
	if len(acrValues) == 0 {
		return nil
	}

	fallback := acrValues
	supported := h.Provider.GetOpenIDConfiguration().ACRValuesSupported

	securityLevel, err := request2.LoginURLParameter(r, request2.SecurityLevelURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("acr_values", securityLevel)
	return nil
}

func (h *Handler) withLocale(r *http.Request, v url.Values) error {
	uiLocales := h.Provider.GetClientConfiguration().GetUILocales()
	if len(uiLocales) == 0 {
		return nil
	}

	fallback := uiLocales
	supported := h.Provider.GetOpenIDConfiguration().UILocalesSupported

	locale, err := request2.LoginURLParameter(r, request2.LocaleURLParameter, fallback, supported)
	if err != nil {
		return err
	}

	v.Add("ui_locales", locale)
	return nil
}
