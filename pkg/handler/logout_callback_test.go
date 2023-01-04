package handler_test

import (
	"testing"

	"github.com/nais/wonderwall/pkg/mock"
)

func TestLogoutCallback(t *testing.T) {
	cfg := mock.Config()
	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)
	logout(t, rpClient, idp)
}
