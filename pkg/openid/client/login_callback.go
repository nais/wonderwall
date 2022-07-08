package client

type LoginCallback struct {
	Client
}

func (in LoginCallback) IdentityProviderError() (bool, error) {
	// TODO
	panic("not implemented")
}

func (in LoginCallback) ValidateRequest() error {
	// TODO
	panic("not implemented")
}

func (in LoginCallback) RedeemCode() error {
	// TODO
	panic("not implemented")
}

func (in LoginCallback) ParseAndValidateTokens() error {
	// TODO
	panic("not implemented")
}
