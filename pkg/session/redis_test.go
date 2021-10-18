//go:build integration
// +build integration

package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/nais/liberator/pkg/keygen"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/session"
)

func TestRedis(t *testing.T) {
	key, err := keygen.Keygen(32)
	assert.NoError(t, err)
	crypter := cryptutil.New(key)

	data := session.NewData("myid", "accesstoken", "idtoken")

	encryptedData, err := data.Encrypt(crypter)
	assert.NoError(t, err)

	client := redis.NewClient(&redis.Options{
		Network: "tcp",
		Addr:    "127.0.0.1:6379",
	})

	sess := session.NewRedis(client)
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
