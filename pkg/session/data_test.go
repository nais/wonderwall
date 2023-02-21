package session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/session"
)

func TestData_HasAccessToken(t *testing.T) {
	data := session.Data{}
	assert.False(t, data.HasAccessToken())

	data.AccessToken = "some-access-token"
	assert.True(t, data.HasAccessToken())
}

func TestData_HasRefreshToken(t *testing.T) {
	data := session.Data{}
	assert.False(t, data.HasRefreshToken())

	data.RefreshToken = "some-refresh-token"
	assert.True(t, data.HasRefreshToken())
}

func TestNewMetadata(t *testing.T) {
	tokenLifetime := 30 * time.Minute
	sessionLifetime := time.Hour

	metadata := session.NewMetadata(tokenLifetime, sessionLifetime)

	maxDelta := time.Second

	expected := time.Now()
	actual := metadata.Session.CreatedAt
	assert.WithinDuration(t, expected, actual, maxDelta)

	expected = time.Now().Add(sessionLifetime)
	actual = metadata.Session.EndsAt
	assert.WithinDuration(t, expected, actual, maxDelta)

	assert.True(t, metadata.Session.TimeoutAt.IsZero())

	expected = time.Now()
	actual = metadata.Tokens.RefreshedAt
	assert.WithinDuration(t, expected, actual, maxDelta)

	expected = time.Now().Add(tokenLifetime)
	actual = metadata.Tokens.ExpireAt
	assert.WithinDuration(t, expected, actual, maxDelta)
}

func TestMetadata_WithTimeout(t *testing.T) {
	tokenLifetime := 30 * time.Minute
	sessionLifetime := time.Hour
	sessionInactivityTimeout := 15 * time.Minute
	maxDelta := time.Second

	metadata := session.NewMetadata(tokenLifetime, sessionLifetime)
	assert.WithinDuration(t, time.Now().Add(tokenLifetime), metadata.Tokens.ExpireAt, maxDelta)

	metadata.WithTimeout(sessionInactivityTimeout)
	assert.False(t, metadata.Session.TimeoutAt.IsZero())
	assert.WithinDuration(t, time.Now().Add(sessionInactivityTimeout), metadata.Tokens.ExpireAt, maxDelta)
	assert.WithinDuration(t, metadata.Session.TimeoutAt, metadata.Tokens.ExpireAt, maxDelta)

	expected := time.Now().Add(sessionInactivityTimeout)
	actual := metadata.Session.TimeoutAt
	assert.WithinDuration(t, expected, actual, maxDelta)

	previousTimeoutAt := metadata.Session.TimeoutAt
	time.Sleep(100 * time.Millisecond)
	metadata.WithTimeout(sessionInactivityTimeout)
	assert.True(t, metadata.Session.TimeoutAt.After(previousTimeoutAt))
}

func TestMetadata_IsExpired(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				ExpireAt: time.Now().Add(-time.Second),
			},
		}

		assert.True(t, metadata.IsExpired())
	})

	t.Run("not expired", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				ExpireAt: time.Now().Add(time.Second),
			},
		}

		assert.False(t, metadata.IsExpired())
	})
}

func TestMetadata_IsRefreshOnCooldown(t *testing.T) {
	t.Run("delta to last refresh below minimum interval", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now(),
				ExpireAt:    time.Now().Add(time.Minute),
			},
		}

		assert.True(t, metadata.IsRefreshOnCooldown())
	})

	t.Run("delta to last refresh above minimum interval", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now().Add(-2 * time.Minute),
				ExpireAt:    time.Now().Add(time.Minute),
			},
		}

		assert.False(t, metadata.IsRefreshOnCooldown())
	})
}

func TestMetadata_NextRefresh(t *testing.T) {
	t.Run("delta to last refresh below minimum interval", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now(),
				ExpireAt:    time.Now().Add(time.Minute),
			},
		}

		assert.True(t, metadata.IsRefreshOnCooldown())
	})

	t.Run("delta to last refresh above minimum interval", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now().Add(-2 * time.Minute),
				ExpireAt:    time.Now().Add(time.Minute),
			},
		}

		assert.False(t, metadata.IsRefreshOnCooldown())
	})
}

func TestMetadata_Refresh(t *testing.T) {
	metadata := session.Metadata{
		Tokens: session.MetadataTokens{
			RefreshedAt: time.Now(),
			ExpireAt:    time.Now().Add(time.Minute),
		},
	}

	prevRefreshedAt := metadata.Tokens.RefreshedAt
	prevExpireAt := metadata.Tokens.ExpireAt

	nextExpirySeconds := int64((2 * time.Minute).Seconds())
	metadata.Refresh(nextExpirySeconds)

	assert.True(t, metadata.Tokens.RefreshedAt.After(prevRefreshedAt))
	assert.True(t, metadata.Tokens.ExpireAt.After(prevExpireAt))
}

func TestMetadata_RefreshCooldown(t *testing.T) {
	t.Run("token lifetime less than interval", func(t *testing.T) {
		tokenLifetime := time.Minute

		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now(),
				ExpireAt:    time.Now().Add(tokenLifetime),
			},
		}

		expected := time.Now().Add(tokenLifetime / 2)
		assert.WithinDuration(t, expected, metadata.RefreshCooldown(), time.Second)
	})

	t.Run("token lifetime longer than interval", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now(),
				ExpireAt:    time.Now().Add(time.Hour),
			},
		}

		expected := metadata.Tokens.RefreshedAt.Add(session.RefreshMinInterval)
		assert.WithinDuration(t, expected, metadata.RefreshCooldown(), time.Second)
	})
}

func TestMetadata_ShouldRefresh(t *testing.T) {
	t.Run("refresh is on cooldown", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now(),
				ExpireAt:    time.Now().Add(time.Minute),
			},
		}

		assert.False(t, metadata.ShouldRefresh())
	})

	t.Run("token is not within expiry range", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now(),
				ExpireAt:    time.Now().Add(time.Hour),
			},
		}

		assert.False(t, metadata.ShouldRefresh())
	})

	t.Run("token is about to expire", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now().Add(-5 * time.Minute),
				ExpireAt:    time.Now().Add(time.Minute),
			},
		}

		assert.True(t, metadata.ShouldRefresh())
	})

	t.Run("token has expired", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now().Add(-5 * time.Minute),
				ExpireAt:    time.Now().Add(-5 * time.Minute),
			},
		}

		assert.True(t, metadata.ShouldRefresh())
	})

	t.Run("refresh is on cooldown and token has expired", func(t *testing.T) {
		metadata := session.Metadata{
			Tokens: session.MetadataTokens{
				RefreshedAt: time.Now(),
				ExpireAt:    time.Now().Add(-5 * time.Minute),
			},
		}

		assert.True(t, metadata.ShouldRefresh())
	})
}

func TestMetadata_TokenLifetime(t *testing.T) {
	metadata := session.Metadata{
		Tokens: session.MetadataTokens{
			RefreshedAt: time.Now(),
			ExpireAt:    time.Now().Add(time.Minute),
		},
	}

	assert.Equal(t, time.Minute, metadata.TokenLifetime().Truncate(time.Second))
}

func TestMetadata_Verbose(t *testing.T) {
	tokenLifetime := 30 * time.Minute
	sessionLifetime := time.Hour

	metadata := session.NewMetadata(tokenLifetime, sessionLifetime)

	verbose := metadata.Verbose()
	maxDelta := time.Second

	expected := time.Now().Add(sessionLifetime)
	actual := time.Now().Add(durationSeconds(verbose.Session.EndsInSeconds))
	assert.WithinDuration(t, expected, actual, maxDelta)

	expected = time.Now().Add(tokenLifetime)
	actual = time.Now().Add(durationSeconds(verbose.Tokens.ExpireInSeconds))
	assert.WithinDuration(t, expected, actual, maxDelta)

	assert.True(t, verbose.Session.Active)
	assert.True(t, verbose.Session.TimeoutAt.IsZero())
	assert.Equal(t, int64(-1), verbose.Session.TimeoutInSeconds)
}

func TestMetadata_VerboseWithRefresh(t *testing.T) {
	tokenLifetime := 30 * time.Minute
	sessionLifetime := time.Hour

	metadata := session.NewMetadata(tokenLifetime, sessionLifetime)

	verbose := metadata.VerboseWithRefresh()
	maxDelta := time.Second

	expected := time.Now().Add(sessionLifetime)
	actual := time.Now().Add(durationSeconds(verbose.Session.EndsInSeconds))
	assert.WithinDuration(t, expected, actual, maxDelta)

	expected = time.Now().Add(tokenLifetime)
	actual = time.Now().Add(durationSeconds(verbose.Tokens.ExpireInSeconds))
	assert.WithinDuration(t, expected, actual, maxDelta)

	expected = time.Now().Add(tokenLifetime).Add(-session.RefreshLeeway)
	actual = time.Now().Add(durationSeconds(verbose.Tokens.NextAutoRefreshInSeconds))
	assert.WithinDuration(t, expected, actual, maxDelta)

	t.Run("refresh on cooldown", func(t *testing.T) {
		assert.True(t, verbose.Tokens.RefreshCooldown)

		expected = time.Now().Add(session.RefreshMinInterval)
		actual = time.Now().Add(durationSeconds(verbose.Tokens.RefreshCooldownSeconds))
		assert.WithinDuration(t, expected, actual, maxDelta)
	})

	t.Run("refresh not on cooldown", func(t *testing.T) {
		metadata := session.NewMetadata(tokenLifetime, sessionLifetime)
		metadata.Tokens.RefreshedAt = time.Now().Add(-5 * time.Minute)
		verbose := metadata.VerboseWithRefresh()

		assert.False(t, verbose.Tokens.RefreshCooldown)
		assert.Equal(t, int64(0), verbose.Tokens.RefreshCooldownSeconds)
	})
}

func TestMetadata_Verbose_WithTimeout(t *testing.T) {
	tokenLifetime := 30 * time.Minute
	sessionLifetime := time.Hour
	timeout := 15 * time.Minute

	metadata := session.NewMetadata(tokenLifetime, sessionLifetime)
	metadata.WithTimeout(timeout)

	maxDelta := time.Second

	verbose := metadata.Verbose()

	assert.True(t, verbose.Session.Active)
	assert.False(t, verbose.Session.TimeoutAt.IsZero())

	expected := time.Now().Add(timeout)
	actual := verbose.Session.TimeoutAt
	assert.WithinDuration(t, expected, actual, maxDelta)

	expected = time.Now().Add(durationSeconds(verbose.Session.TimeoutInSeconds))
	actual = verbose.Session.TimeoutAt
	assert.WithinDuration(t, expected, actual, maxDelta)
}

func TestMetadata_IsTimedOut(t *testing.T) {
	tokenLifetime := 30 * time.Minute
	sessionLifetime := time.Hour

	t.Run("timeout is zero", func(t *testing.T) {
		metadata := session.NewMetadata(tokenLifetime, sessionLifetime)
		assert.False(t, metadata.IsTimedOut())
	})

	t.Run("timeout is non-zero", func(t *testing.T) {
		timeout := 15 * time.Minute

		metadata := session.NewMetadata(tokenLifetime, sessionLifetime)
		metadata.WithTimeout(timeout)
		assert.False(t, metadata.IsTimedOut())

		metadata.WithTimeout(-timeout)
		assert.True(t, metadata.IsTimedOut())
	})
}

func durationSeconds(seconds int64) time.Duration {
	return time.Duration(seconds) * time.Second
}
