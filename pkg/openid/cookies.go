package openid

type LoginCookie struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	Referer      string `json:"referer"`
}

type LogoutCookie struct {
	State      string `json:"state"`
	RedirectTo string `json:"redirect_to"`
}
