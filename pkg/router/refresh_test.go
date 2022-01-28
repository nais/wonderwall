package router

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var cfg = config.Config{
	EncryptionKey: `G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`, // 256 bits AES
	Ingress:       "/",
	OpenID: config.OpenID{
		Provider: "test",
	},
	RefreshToken: true,
}

func newHandler(provider openid.Provider) *Handler {
	crypter := crypto.NewCrypter([]byte(cfg.EncryptionKey))
	sessionStore := session.NewMemory()

	h, err := NewHandler(cfg, crypter, zerolog.Logger{}, provider, sessionStore)
	if err != nil {
		panic(err)
	}

	h.Cookies = h.Cookies.WithSecure(false)
	return h
}

func TestHandler_RefreshTest(t *testing.T) {
	_, idp := mock.IdentityProviderServer()
	h := newHandler(idp)

	expires := int64(20000)

	accessToken := jwt.New()
	accessToken.Set("sub", "client_id")
	accessToken.Set("iss", idp.GetOpenIDConfiguration().Issuer)
	accessToken.Set("acr", idp.ClientConfiguration.GetACRValues())
	accessToken.Set("iat", time.Now().Unix())
	accessToken.Set("exp", time.Now().Unix()+expires)
	signedAccessToken, err := signToken(idp, accessToken)
	assert.NoError(t, err)

	refreshToken := jwt.New()
	refreshToken.Set("sub", "client_id")
	refreshToken.Set("iss", idp.GetOpenIDConfiguration().Issuer)
	refreshToken.Set("iat", time.Now().Unix())
	refreshToken.Set("exp", time.Now().Unix()+expires)
	signedRefreshToken, err := signToken(idp, refreshToken)
	assert.NoError(t, err)

	sessionData := &session.Data{
		ExternalSessionID: "session_id",
		AccessToken:       signedAccessToken,
		IDToken:           "id_token",
		RefreshToken:      signedRefreshToken,
	}

	h.Config.SessionMaxLifetime = 10 * time.Second

	err = h.RefreshSession(context.Background(), sessionData, nil, nil)
	assert.NoError(t, err)
}

func signToken(idp mock.TestProvider, token jwt.Token) (string, error) {
	privateJwkSet := *idp.PrivateJwkSet()
	signer, ok := privateJwkSet.Get(0)
	if !ok {
		return "", fmt.Errorf("could not get signer")
	}

	signedToken, err := jwt.Sign(token, jwa.RS256, signer)
	if err != nil {
		return "", err
	}

	return string(signedToken), nil
}
