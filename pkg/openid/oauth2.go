package openid

import (
	"fmt"
	"net/url"

	"golang.org/x/oauth2"
)

// TokenResponse is the struct representing the HTTP response from authorization servers as defined in RFC 6749, section 5.1.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// PushedAuthorizationResponse is the struct representing the HTTP response from authorization servers as defined in RFC 9126, section 2.2.
type PushedAuthorizationResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// TokenErrorResponse is the struct representing the HTTP error response returned from authorization servers as defined in RFC 6749, section 5.2.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type AuthParams map[string]string

// AuthCodeOptions adds AuthParams to the given [oauth2.AuthCodeOption] slice and returns the updated slice.
func (a AuthParams) AuthCodeOptions(opts []oauth2.AuthCodeOption) []oauth2.AuthCodeOption {
	for key, val := range a {
		opts = append(opts, oauth2.SetAuthURLParam(key, val))
	}

	return opts
}

// URLValues adds AuthParams to the given map of parameters and returns a [url.Values].
func (a AuthParams) URLValues(params map[string]string) url.Values {
	v := url.Values{}

	for key, val := range params {
		v.Set(key, val)
	}

	for key, val := range a {
		v.Set(key, val)
	}

	return v
}

// AuthParamsClientSecret returns a map of parameters to be sent to the authorization server when using a client secret for client authentication in RFC 6749, section 2.3.1.
// The target authorization server must support the "client_secret_post" client authentication method.
func AuthParamsClientSecret(clientSecret string) AuthParams {
	return map[string]string{
		"client_secret": clientSecret,
	}
}

// AuthParamsJwtBearer returns a map of parameters to be sent to the authorization server when using a JWT for client authentication in RFC 7523, section 2.2.
// The target authorization server must support the "private_key_jwt" client authentication method.
func AuthParamsJwtBearer(clientAssertion string) AuthParams {
	return map[string]string{
		"client_assertion":      clientAssertion,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}
}

func RedirectURIOption(redirectUri string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("redirect_uri", redirectUri)
}

func StateMismatchError(queryParams url.Values, expectedState string) error {
	actualState := queryParams.Get("state")

	if len(actualState) <= 0 {
		return fmt.Errorf("missing state parameter in request (possible csrf)")
	}

	if expectedState != actualState {
		return fmt.Errorf("state parameter mismatch (possible csrf): expected %s, got %s", expectedState, actualState)
	}

	return nil
}
