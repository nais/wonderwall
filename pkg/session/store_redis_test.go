package session_test

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/session"
)

func TestRedis(t *testing.T) {
	crypter := makeCrypter(t)
	data := makeData()
	encryptedData, err := data.Encrypt(crypter)
	assert.NoError(t, err)

	s, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer s.Close()

	client := redis.NewClient(&redis.Options{
		Network: "tcp",
		Addr:    s.Addr(),
	})

	store := session.NewRedis(client)
	key := "key"

	write(t, store, key, encryptedData)

	decrypted := read(t, store, key, encryptedData, crypter)
	decryptedEqual(t, data, decrypted)

	data, encryptedData = update(t, store, key, data, crypter)

	decrypted = read(t, store, key, encryptedData, crypter)
	decryptedEqual(t, data, decrypted)

	del(t, store, key)
}
