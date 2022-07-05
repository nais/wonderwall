package client

type LogoutCallback struct {
	Client
}

func (in LogoutCallback) ValidateRequest() (bool, error) {
	panic("not implemented")
}
