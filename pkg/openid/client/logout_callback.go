package client

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/nais/wonderwall/pkg/openid"
)

type LogoutCallback interface {
	ValidateRequest() error
}

type logoutCallback struct {
	cookie        *openid.LogoutCookie
	requestParams url.Values
}

func NewLogoutCallback(r *http.Request, cookie *openid.LogoutCookie) LogoutCallback {
	return &logoutCallback{
		requestParams: r.URL.Query(),
		cookie:        cookie,
	}
}

func (in logoutCallback) ValidateRequest() error {
	if err := in.emptyRedirectError(); err != nil {
		return err
	}

	if err := in.stateMismatchError(); err != nil {
		return err
	}

	return nil
}

func (in logoutCallback) emptyRedirectError() error {
	if len(in.cookie.RedirectTo) == 0 {
		return fmt.Errorf("empty redirect")
	}

	return nil
}

func (in logoutCallback) stateMismatchError() error {
	expectedState := in.cookie.State
	actualState := in.requestParams.Get("state")

	if len(actualState) <= 0 {
		return fmt.Errorf("missing state parameter in request (possible csrf)")
	}

	if expectedState != actualState {
		return fmt.Errorf("state parameter mismatch (possible csrf): expected %s, got %s", expectedState, actualState)
	}

	return nil
}
