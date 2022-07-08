package client

import "github.com/nais/wonderwall/pkg/openid"

type Logout struct {
	Client
}

func (in Logout) URL() string {
	// TODO
	panic("not implemented")
}

func (in Logout) Cookie() openid.LogoutCookie {
	// TODO
	panic("not implemented")
}
