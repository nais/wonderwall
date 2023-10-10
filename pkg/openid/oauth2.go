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

// TokenErrorResponse is the struct representing the HTTP error response returned from authorization servers as defined in RFC 6749, section 5.2.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// JwtAuthenticationParameters returns a map of parameters to be sent to the authorization server when using a JWT for client authentication in RFC 7523, section 2.2.
func JwtAuthenticationParameters(clientAssertion string) map[string]string {
	return map[string]string{
		"client_assertion":      clientAssertion,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}
}

func WithJwtAuthentication(opts []oauth2.AuthCodeOption, clientAssertion string) []oauth2.AuthCodeOption {
	for k, v := range JwtAuthenticationParameters(clientAssertion) {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}

	return opts
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
