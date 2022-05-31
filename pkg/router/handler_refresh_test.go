package router

import (
	"context"
	"fmt"
	jw "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	jwt "github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/rs/zerolog"
	log "github.com/sirupsen/logrus"
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

	h.CookieOptions = h.CookieOptions.WithSecure(false)
	return h
}

func TestHandler_RefreshTest(t *testing.T) {
	_, idp := mock.IdentityProviderServer()
	h := newHandler(idp)
	ctx := context.Background()

	for _, test := range []struct {
		name                string
		accessTokenExpires  int64
		refreshTokenExpires int64
		sessionMaxLifeTime  time.Duration
		timesToRefresh      int64
		refreshToggle       bool
	}{
		{
			name:                "Expired access token should be updated with refresh token",
			accessTokenExpires:  int64(2 * time.Second),
			refreshTokenExpires: int64(4 * time.Second),
			sessionMaxLifeTime:  10 * time.Second,
			refreshToggle:       true,
			timesToRefresh:      1,
		},
		{
			name:                "Access token not expired should not be updated",
			accessTokenExpires:  int64(15 * time.Second),
			refreshTokenExpires: int64(45 * time.Second),
			sessionMaxLifeTime:  20 * time.Second,
			refreshToggle:       true,
			timesToRefresh:      1,
		},
		{
			name:                "Refresh toggle not activated, should not refresh tokens",
			accessTokenExpires:  int64(15 * time.Second),
			refreshTokenExpires: int64(45 * time.Second),
			sessionMaxLifeTime:  20 * time.Second,
			timesToRefresh:      1,
		},
	} {
		h.Config.SessionMaxLifetime = test.sessionMaxLifeTime

		accessToken := getToken(t, idp, test.accessTokenExpires)
		refreshToken := getToken(t, idp, test.refreshTokenExpires)

		sessionData := &session.Data{
			ExternalSessionID: "session_id",
			AccessToken:       string(accessToken),
			IDToken:           "id_token",
			RefreshToken:      string(refreshToken),
			TimesToRefresh:    test.timesToRefresh,
		}

		publicKeys, err := h.Provider.GetPublicJwkSet(ctx)
		if err != nil {
			fmt.Printf("public keys: %v", err)
		}

		aToken, err := jwt.ParseAccessToken(sessionData.AccessToken, *publicKeys)
		assert.NoError(t, err)
		sessionLifeTime := h.getSessionLifetime(aToken)

		previousAccessToken := sessionData.AccessToken
		previousRefreshToken := sessionData.RefreshToken

		if shouldRefresh(sessionLifeTime, sessionData) {
			err := h.RefreshSession(context.Background(), sessionData, nil, nil)
			assert.NoError(t, err)
			assert.NotEqual(t, previousAccessToken, sessionData.AccessToken)
			assert.NotEqual(t, previousRefreshToken, sessionData.RefreshToken)
		}

		err = h.RefreshSession(context.Background(), sessionData, nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, previousAccessToken, sessionData.AccessToken)
		assert.Equal(t, previousRefreshToken, sessionData.RefreshToken)
	}
}

func signToken(idp mock.TestProvider, token jw.Token) ([]byte, error) {
	privateJwkSet := *idp.PrivateJwkSet()
	signer, ok := privateJwkSet.Key(0)
	if !ok {
		return nil, fmt.Errorf("could not get signer")
	}

	signedToken, err := jw.Sign(token, jw.WithKey(signer.Algorithm(), signer))
	if err != nil {
		log.Fatalf("signing id_token: %+v", err)
	}

	return signedToken, nil
}

func getToken(t *testing.T, idp mock.TestProvider, expires int64) []byte {
	accessToken := jw.New()
	accessToken.Set("sub", "client_id")
	accessToken.Set("iss", idp.GetOpenIDConfiguration().Issuer)
	accessToken.Set("acr", idp.ClientConfiguration.GetACRValues())
	accessToken.Set("iat", time.Now().Unix())
	accessToken.Set("exp", time.Now().Unix()+expires)
	signedAccessToken, err := signToken(idp, accessToken)
	assert.NoError(t, err)

	return signedAccessToken
}
