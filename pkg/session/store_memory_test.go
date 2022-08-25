package session_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/session"
)

func TestMemory(t *testing.T) {
	crypter := makeCrypter(t)
	data := makeData()
	encryptedData, err := data.Encrypt(crypter)
	assert.NoError(t, err)

	store := session.NewMemory()
	key := "key"

	write(t, store, key, encryptedData)

	decrypted := read(t, store, key, encryptedData, crypter)
	decryptedEqual(t, data, decrypted)

	data, encryptedData = update(t, store, key, data, crypter)

	decrypted = read(t, store, key, encryptedData, crypter)
	decryptedEqual(t, data, decrypted)

	del(t, store, key)
}
