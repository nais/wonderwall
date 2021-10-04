package session_test

import (
	"context"
	"github.com/nais/liberator/pkg/keygen"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"testing"
	"time"

	"github.com/nais/wonderwall/pkg/session"
	"github.com/stretchr/testify/assert"
)

func TestMemory(t *testing.T) {
	key, err := keygen.Keygen(32)
	assert.NoError(t, err)
	crypter := cryptutil.New(key)

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
