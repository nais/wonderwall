//go:build integration

package session_test

import (
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/valkey"
)

// valkeyImages are the supported Valkey major versions.
var valkeyImages = []string{
	"valkey/valkey:8",
	"valkey/valkey:9",
}

func TestIntegrationValkey(t *testing.T) {
	for _, image := range valkeyImages {
		t.Run(image, func(t *testing.T) {
			container, err := valkey.Run(t.Context(), image)
			testcontainers.CleanupContainer(t, container)
			require.NoError(t, err)

			uri, err := container.ConnectionString(t.Context())
			require.NoError(t, err)

			opts, err := redis.ParseURL(uri)
			require.NoError(t, err)

			for name, test := range redisTests {
				t.Run(name, func(t *testing.T) {
					client := newRedisClient(t, opts.Addr)
					require.NoError(t, client.FlushDB(t.Context()).Err())
					test(t, client)
				})
			}
		})
	}
}
