package handler_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/session"
)

func TestSession(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Minute
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerbose
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	allowedSkew := 5 * time.Second
	assert.WithinDuration(t, time.Now(), data.Session.CreatedAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(cfg.Session.MaxLifetime), data.Session.EndsAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(idp.ProviderHandler.TokenDuration), data.Tokens.ExpireAt, allowedSkew)
	assert.WithinDuration(t, time.Now(), data.Tokens.RefreshedAt, allowedSkew)

	sessionEndDuration := time.Duration(data.Session.EndsInSeconds) * time.Second
	// 1 second < time until session ends <= configured max session lifetime
	assert.LessOrEqual(t, sessionEndDuration, cfg.Session.MaxLifetime)
	assert.Greater(t, sessionEndDuration, time.Second)

	tokenExpiryDuration := time.Duration(data.Tokens.ExpireInSeconds) * time.Second
	// 1 second < time until token expires <= max duration for tokens from IDP
	assert.LessOrEqual(t, tokenExpiryDuration, idp.ProviderHandler.TokenDuration)
	assert.Greater(t, tokenExpiryDuration, time.Second)

	assert.True(t, data.Session.Active)
	assert.True(t, data.Session.TimeoutAt.IsZero())
	assert.Equal(t, int64(-1), data.Session.TimeoutInSeconds)
}

func TestSession_WithInactivity(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true
	cfg.Session.Inactivity = true
	cfg.Session.InactivityTimeout = 10 * time.Minute

	idp := mock.NewIdentityProvider(cfg)
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerbose
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	maxDelta := 5 * time.Second

	assert.True(t, data.Session.Active)
	assert.False(t, data.Session.TimeoutAt.IsZero())

	expectedTimeoutAt := time.Now().Add(cfg.Session.InactivityTimeout)
	assert.WithinDuration(t, expectedTimeoutAt, data.Session.TimeoutAt, maxDelta)

	actualTimeoutDuration := time.Duration(data.Session.TimeoutInSeconds) * time.Second
	assert.WithinDuration(t, expectedTimeoutAt, time.Now().Add(actualTimeoutDuration), maxDelta)
}

func TestSession_WithRefresh(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Minute
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	allowedSkew := 5 * time.Second
	assert.WithinDuration(t, time.Now(), data.Session.CreatedAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(cfg.Session.MaxLifetime), data.Session.EndsAt, allowedSkew)
	assert.WithinDuration(t, time.Now().Add(idp.ProviderHandler.TokenDuration), data.Tokens.ExpireAt, allowedSkew)
	assert.WithinDuration(t, time.Now(), data.Tokens.RefreshedAt, allowedSkew)

	sessionEndDuration := time.Duration(data.Session.EndsInSeconds) * time.Second
	// 1 second < time until session ends <= configured max session lifetime
	assert.LessOrEqual(t, sessionEndDuration, cfg.Session.MaxLifetime)
	assert.Greater(t, sessionEndDuration, time.Second)

	tokenExpiryDuration := time.Duration(data.Tokens.ExpireInSeconds) * time.Second
	// 1 second < time until token expires <= max duration for tokens from IDP
	assert.LessOrEqual(t, tokenExpiryDuration, idp.ProviderHandler.TokenDuration)
	assert.Greater(t, tokenExpiryDuration, time.Second)

	// 1 second < next token refresh <= seconds until token expires
	assert.LessOrEqual(t, data.Tokens.NextAutoRefreshInSeconds, data.Tokens.ExpireInSeconds)
	assert.Greater(t, data.Tokens.NextAutoRefreshInSeconds, int64(1))

	assert.True(t, data.Tokens.RefreshCooldown)
	// 1 second < refresh cooldown <= minimum refresh interval
	assert.LessOrEqual(t, data.Tokens.RefreshCooldownSeconds, session.RefreshMinInterval)
	assert.Greater(t, data.Tokens.RefreshCooldownSeconds, int64(1))

	assert.True(t, data.Session.Active)
	assert.True(t, data.Session.TimeoutAt.IsZero())
	assert.Equal(t, int64(-1), data.Session.TimeoutInSeconds)
}
