package openid

type Logout struct {
	Client
}

func (in Logout) URL() string {
	panic("not implemented")
}

func (in Logout) Cookie() LogoutCookie {
	panic("not implemented")
}
