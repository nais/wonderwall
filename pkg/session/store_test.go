package session_test

import (
	"context"
	"testing"
	"time"

	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nais/liberator/pkg/keygen"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
)

func decryptedEqual(t *testing.T, expected, actual *session.Data) {
	assert.Equal(t, expected.AccessToken, actual.AccessToken)
	assert.Equal(t, expected.RefreshToken, actual.RefreshToken)
	assert.Equal(t, expected.IDToken, actual.IDToken)
	assert.Equal(t, expected.IDTokenJwtID, actual.IDTokenJwtID)
	assert.Equal(t, expected.ExternalSessionID, actual.ExternalSessionID)

	assert.WithinDuration(t, expected.Metadata.Session.CreatedAt, actual.Metadata.Session.CreatedAt, 0)
	assert.WithinDuration(t, expected.Metadata.Session.EndsAt, actual.Metadata.Session.EndsAt, 0)
	assert.WithinDuration(t, expected.Metadata.Tokens.ExpireAt, actual.Metadata.Tokens.ExpireAt, 0)
	assert.WithinDuration(t, expected.Metadata.Tokens.RefreshedAt, actual.Metadata.Tokens.RefreshedAt, 0)
}

func makeCrypter(t *testing.T) crypto.Crypter {
	key, err := keygen.Keygen(32)
	assert.NoError(t, err)
	return crypto.NewCrypter(key)
}

func makeData() *session.Data {
	idToken := jwtlib.New()
	idToken.Set("jti", "id-token-jti")

	accessToken := "some-access-token"
	refreshToken := "some-refresh-token"

	tokens := &openid.Tokens{
		AccessToken:  accessToken,
		IDToken:      openid.NewIDToken("id_token", idToken),
		RefreshToken: refreshToken,
	}

	expiresIn := time.Hour
	endsIn := time.Hour

	metadata := session.NewMetadata(expiresIn, endsIn)
	return session.NewData("myid", tokens, metadata)
}

func write(t *testing.T, store session.Store, key string, value *session.EncryptedData) {
	err := store.Write(context.Background(), key, value, time.Minute)
	assert.NoError(t, err)
}

func read(t *testing.T, store session.Store, key string, encrypted *session.EncryptedData, crypter crypto.Crypter) *session.Data {
	result, err := store.Read(context.Background(), key)
	assert.NoError(t, err)
	assert.Equal(t, encrypted, result)

	decrypted, err := result.Decrypt(crypter)
	assert.NoError(t, err)

	return decrypted
}

func update(t *testing.T, store session.Store, key string, data *session.Data, crypter crypto.Crypter) (*session.Data, *session.EncryptedData) {
	data.AccessToken = "new-access-token"
	data.RefreshToken = "new-refresh-token"
	encryptedData, err := data.Encrypt(crypter)
	assert.NoError(t, err)

	err = store.Update(context.Background(), key, encryptedData)
	assert.NoError(t, err)

	return data, encryptedData
}

func del(t *testing.T, store session.Store, key string) {
	err := store.Delete(context.Background(), key)
	assert.NoError(t, err)

	result, err := store.Read(context.Background(), key)
	assert.Error(t, err)
	assert.ErrorIs(t, err, session.ErrNotFound)
	assert.Nil(t, result)
}
