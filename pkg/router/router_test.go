package router_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/router"
)

func TestJWK(t *testing.T) {
	key := &jose.JSONWebKey{}
	_ = json.Unmarshal([]byte(``), key)
}

func TestLoginURL(t *testing.T) {
	handler := &router.Handler{
		Config: config.IDPorten{
			ClientID:    "clientid",
			RedirectURI: "http://localhost/redirect",
			WellKnown: config.IDPortenWellKnown{
				AuthorizationEndpoint: "http://localhost:1234/authorize",
			},
			Locale:        "nb",
			SecurityLevel: "Level4",
		},
	}
	_, err := handler.LoginURL()
	assert.NoError(t, err)
}
