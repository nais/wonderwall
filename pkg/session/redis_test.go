// +build integration

package session_test

import (
	"context"
	"github.com/go-redis/redis/v8"
	"github.com/nais/wonderwall/pkg/session"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"testing"
	"time"
)

func TestRedis(t *testing.T) {
	data := &session.Data{
		ExternalSessionID: "myid",
		Token: &oauth2.Token{
			AccessToken: "axx",
		},
	}

	client := redis.NewClient(&redis.Options{
		Network: "tcp",
		Addr:    "127.0.0.1:6379",
	})

	sess := session.NewRedis(client)
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
