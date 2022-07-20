package client

type Logout interface {
	SingleLogoutURL(idToken string) string
}

type logout struct {
	Client
}

func NewLogout(c Client) Logout {
	return &logout{
		Client: c,
	}
}

func (in *logout) SingleLogoutURL(idToken string) string {
	endSessionEndpoint := in.config().Provider().EndSessionEndpointURL()
	v := endSessionEndpoint.Query()
	v.Add("post_logout_redirect_uri", in.config().Client().LogoutCallbackURI())

	if len(idToken) > 0 {
		v.Add("id_token_hint", idToken)
	}

	endSessionEndpoint.RawQuery = v.Encode()
	return endSessionEndpoint.String()
}
