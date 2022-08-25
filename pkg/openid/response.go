package openid

// TokenResponse is the struct representing the HTTP response from OpenID Connect providers returning a token in
// JSON form.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// TokenErrorResponse is the struct representing the HTTP error response returned from OpenID Connect providers
// in JSON form.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
