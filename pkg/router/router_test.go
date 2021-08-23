package router_test

import (
	"github.com/nais/wonderwall/pkg/cryptutil"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/stretchr/testify/assert"
)

var encryptionKey = []byte(`G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`) // 256 bits AES

var cfg = config.IDPorten{
	ClientID:     "clientid",
	ClientJWK:    "",
	RedirectURI:  "http://localhost/redirect",
	WellKnownURL: "",
	WellKnown: config.IDPortenWellKnown{
		AuthorizationEndpoint: "http://localhost:1234/authorize",
	},
	Locale:                "nb",
	SecurityLevel:         "Level4",
	PostLogoutRedirectURI: "",
}

func TestLoginURL(t *testing.T) {
	handler := &router.Handler{
		Config: cfg,
	}
	_, err := handler.LoginURL()
	assert.NoError(t, err)
}

func TestHandler_Login(t *testing.T) {
	handler := &router.Handler{
		Config: cfg,
		OauthConfig: oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "auth-url",
				TokenURL: "token-url",
			},
			RedirectURL: "redirect-url",
			Scopes:      []string{"scopes"},
		},
		Crypter:         cryptutil.New(encryptionKey),
		UpstreamHost:    "",
		IdTokenVerifier: nil,
	}
	r := router.New(handler)
	server := httptest.NewServer(r)

	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := client.Get(server.URL + "/oauth2/login")

	assert.NoError(t, err)
	defer req.Body.Close()

	location := req.Header.Get("location")
	u, err := url.Parse(location)
	assert.NoError(t, err)

	assert.Equal(t, "localhost:1234", u.Host)
	assert.Equal(t, "/authorize", u.Path)
	assert.Equal(t, cfg.SecurityLevel, u.Query().Get("acr_values"))
	assert.Equal(t, cfg.ClientID, u.Query().Get("client_id"))
	assert.Equal(t, cfg.RedirectURI, u.Query().Get("redirect_uri"))
	assert.NotEmpty(t, u.Query().Get("state"))
	assert.NotEmpty(t, u.Query().Get("nonce"))
	assert.NotEmpty(t, u.Query().Get("code_challenge"))
}
