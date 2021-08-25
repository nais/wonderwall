package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/session"
)

func TestMemory(t *testing.T) {
	data := &session.Data{
		ExternalSessionID: "myid",
		Token: &oauth2.Token{
			AccessToken: "axx",
		},
	}

	sess := session.NewMemory()
	err := sess.Write(context.Background(), "key", data, time.Minute)
	assert.NoError(t, err)

	result, err := sess.Read(context.Background(), "key")
	assert.NoError(t, err)
	assert.Equal(t, data, result)

	err = sess.Delete(context.Background(), "key")

	result, err = sess.Read(context.Background(), "key")
	assert.Error(t, err)
	assert.Nil(t, result)
}
