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

	for _, test := range []struct {
		name                string
		accessTokenExpires  int64
		refreshTokenExpires int64
		sessionMaxLifeTime  time.Duration
		refreshToggle       bool
	}{
		{
			name:                "Expired access token should be updated with refresh token",
			accessTokenExpires:  int64(2 * time.Second),
			refreshTokenExpires: int64(4 * time.Second),
			sessionMaxLifeTime:  10 * time.Second,
			refreshToggle:       true,
		},
		{
			name:                "Access token not expired should not be updated",
			accessTokenExpires:  int64(15 * time.Second),
			refreshTokenExpires: int64(45 * time.Second),
			sessionMaxLifeTime:  20 * time.Second,
			refreshToggle:       true,
		},
		{
			name:                "Refresh toggle not activated, should not refresh tokens",
			accessTokenExpires:  int64(15 * time.Second),
			refreshTokenExpires: int64(45 * time.Second),
			sessionMaxLifeTime:  20 * time.Second,
		},
	} {
		h.Config.SessionMaxLifetime = test.sessionMaxLifeTime

		accessToken := getToken(t, idp, test.accessTokenExpires)
		refreshToken := getToken(t, idp, test.refreshTokenExpires)

		sessionData := &session.Data{
			ExternalSessionID: "session_id",
			AccessToken:       accessToken,
			IDToken:           "id_token",
			RefreshToken:      refreshToken,
		}

		sessionLifeTime, _ := h.getSessionLifetime(sessionData.AccessToken)

		previousAccessToken := sessionData.AccessToken
		previousRefreshToken := sessionData.RefreshToken

		if IsUpdate(sessionLifeTime) {
			err := h.RefreshSession(context.Background(), sessionData, nil, nil)
			assert.NoError(t, err)
			assert.NotEqual(t, previousAccessToken, sessionData.AccessToken)
			assert.NotEqual(t, previousRefreshToken, sessionData.RefreshToken)
		}

		err := h.RefreshSession(context.Background(), sessionData, nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, previousAccessToken, sessionData.AccessToken)
		assert.Equal(t, previousRefreshToken, sessionData.RefreshToken)
	}
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

func getToken(t *testing.T, idp mock.TestProvider, expires int64) string {
	accessToken := jwt.New()
	accessToken.Set("sub", "client_id")
	accessToken.Set("iss", idp.GetOpenIDConfiguration().Issuer)
	accessToken.Set("acr", idp.ClientConfiguration.GetACRValues())
	accessToken.Set("iat", time.Now().Unix())
	accessToken.Set("exp", time.Now().Unix()+expires)
	signedAccessToken, err := signToken(idp, accessToken)
	assert.NoError(t, err)

	return signedAccessToken
}
