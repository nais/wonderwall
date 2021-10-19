package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/nais/liberator/pkg/keygen"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/session"
)

func TestMemory(t *testing.T) {
	key, err := keygen.Keygen(32)
	assert.NoError(t, err)
	crypter := crypto.NewCrypter(key)

	data := session.NewData("myid", "accesstoken", "idtoken")

	encryptedData, err := data.Encrypt(crypter)
	assert.NoError(t, err)

	sess := session.NewMemory()
	err = sess.Write(context.Background(), "key", encryptedData, time.Minute)
	assert.NoError(t, err)

	result, err := sess.Read(context.Background(), "key")
	assert.NoError(t, err)
	assert.Equal(t, encryptedData, result)

	decrypted, err := result.Decrypt(crypter)
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)

	err = sess.Delete(context.Background(), "key")

	result, err = sess.Read(context.Background(), "key")
	assert.Error(t, err)
	assert.Nil(t, result)
}
