package openid

import (
	"fmt"
	"net/url"

	"github.com/nais/wonderwall/pkg/openid/scopes"

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

// AuthorizationCodeParams represents the (variable) parameters for the authorization code flow.
type AuthorizationCodeParams struct {
	AcrValues    string
	ClientID     string
	CodeVerifier string
	Nonce        string
	Prompt       string
	RedirectURI  string
	Resource     string
	Scope        []string
	State        string
	UILocales    string
}

// AuthParams converts AuthorizationCodeParams the actual parameters to be sent to the authorization server as part of the authorization code flow.
func (a AuthorizationCodeParams) AuthParams() AuthParams {
	params := AuthParams{
		"client_id":             a.ClientID,
		"code_challenge":        oauth2.S256ChallengeFromVerifier(a.CodeVerifier),
		"code_challenge_method": "S256",
		"nonce":                 a.Nonce,
		"redirect_uri":          a.RedirectURI,
		"response_mode":         "query",
		"response_type":         "code",
		"scope":                 strings.Join(a.Scope, " "),
		"state":                 a.State,
	}

	if len(a.AcrValues) > 0 {
		params["acr_values"] = a.AcrValues
	}

	if len(a.UILocales) > 0 {
		params["ui_locales"] = a.UILocales
	}

	if len(a.Prompt) > 0 {
		params["prompt"] = a.Prompt
		params["max_age"] = "0"
	}

	if len(a.Resource) > 0 {
		params["resource"] = a.Resource
	}

	return params
}

// Cookie creates a LoginCookie for storing client-side state as part of the authorization code flow.
func (a AuthorizationCodeParams) Cookie() LoginCookie {
	return LoginCookie{
		Acr:          a.AcrValues,
		CodeVerifier: a.CodeVerifier,
		Nonce:        a.Nonce,
		State:        a.State,
		RedirectURI:  a.RedirectURI,
	}
}

type AuthParams map[string]string

// AuthCodeOptions converts AuthParams to a slice of [oauth2.AuthCodeOption].
func (a AuthParams) AuthCodeOptions() []oauth2.AuthCodeOption {
	opts := make([]oauth2.AuthCodeOption, 0, len(a))

	for key, val := range a {
		opts = append(opts, oauth2.SetAuthURLParam(key, val))
	}

	return opts
}

// URLValues converts AuthParams to a [url.Values].
func (a AuthParams) URLValues() url.Values {
	v := url.Values{}

	for key, val := range a {
		v.Set(key, val)
	}

	return v
}

// Merge merges two AuthParams into one.
// Conflicting keys are overridden by the given AuthParams.
func (a AuthParams) Merge(other AuthParams) AuthParams {
	for key, val := range other {
		a[key] = val
	}

	return a
}

// ClientAuthParamsSecret returns a map of parameters to be sent to the authorization server when using a client secret for client authentication in RFC 6749, section 2.3.1.
// The target authorization server must support the "client_secret_post" client authentication method.
func ClientAuthParamsSecret(clientSecret string) AuthParams {
	return AuthParams{
		"client_secret": clientSecret,
	}
}

// ClientAuthParamsJwtBearer returns a map of parameters to be sent to the authorization server when using a JWT for client authentication in RFC 7523, section 2.2.
// The target authorization server must support the "private_key_jwt" client authentication method.
func ClientAuthParamsJwtBearer(clientAssertion string) AuthParams {
	return AuthParams{
		"client_assertion":      clientAssertion,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}
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
