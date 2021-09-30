package session_test

import (
	"context"
	"github.com/nais/liberator/pkg/keygen"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/session"
)

func TestMemory(t *testing.T) {
	key, err := keygen.Keygen(32)
	assert.NoError(t, err)
	crypter := cryptutil.New(key)

	data := &session.Data{
		ExternalSessionID: "myid",
		OAuth2Token: &oauth2.Token{
			AccessToken: "axx",
		},
		IDTokenSerialized: "idtoken",
	}

	sess := session.NewMemory(crypter)
	err = sess.Write(context.Background(), "key", data, time.Minute)
	assert.NoError(t, err)

	result, err := sess.Read(context.Background(), "key")
	assert.NoError(t, err)
	assert.Equal(t, data, result)

	err = sess.Delete(context.Background(), "key")

	result, err = sess.Read(context.Background(), "key")
	assert.Error(t, err)
	assert.Nil(t, result)
}
