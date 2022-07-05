package client

type LoginCallback struct {
	Client
}

func (in LoginCallback) IdentityProviderError() (bool, error) {
	panic("not implemented")
}

func (in LoginCallback) ValidateRequest() error {
	panic("not implemented")
}

func (in LoginCallback) RedeemCode() error {
	panic("not implemented")
}

func (in LoginCallback) ParseAndValidateTokens() error {
	panic("not implemented")
}
