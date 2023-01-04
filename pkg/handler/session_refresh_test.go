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

func TestSessionRefresh(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Second
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	// get initial session info
	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	// wait until refresh cooldown has reached zero before refresh
	waitForRefreshCooldownTimer(t, idp, rpClient)

	resp = sessionRefresh(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var refreshedData session.MetadataVerboseWithRefresh
	err = json.Unmarshal([]byte(resp.Body), &refreshedData)
	assert.NoError(t, err)

	// session create and end times should be unchanged
	assert.WithinDuration(t, data.Session.CreatedAt, refreshedData.Session.CreatedAt, 0)
	assert.WithinDuration(t, data.Session.EndsAt, refreshedData.Session.EndsAt, 0)

	// token expiration and refresh times should be later than before
	assert.True(t, refreshedData.Tokens.ExpireAt.After(data.Tokens.ExpireAt))
	assert.True(t, refreshedData.Tokens.RefreshedAt.After(data.Tokens.RefreshedAt))

	allowedSkew := 5 * time.Second
	assert.WithinDuration(t, time.Now().Add(idp.ProviderHandler.TokenDuration), refreshedData.Tokens.ExpireAt, allowedSkew)
	assert.WithinDuration(t, time.Now(), refreshedData.Tokens.RefreshedAt, allowedSkew)

	sessionEndDuration := time.Duration(refreshedData.Session.EndsInSeconds) * time.Second
	// 1 second < time until session ends <= configured max session lifetime
	assert.LessOrEqual(t, sessionEndDuration, cfg.Session.MaxLifetime)
	assert.Greater(t, sessionEndDuration, time.Second)

	tokenExpiryDuration := time.Duration(refreshedData.Tokens.ExpireInSeconds) * time.Second
	// 1 second < time until token expires <= max duration for tokens from IDP
	assert.LessOrEqual(t, tokenExpiryDuration, idp.ProviderHandler.TokenDuration)
	assert.Greater(t, tokenExpiryDuration, time.Second)

	// 1 second < next token refresh <= seconds until token expires
	assert.LessOrEqual(t, refreshedData.Tokens.NextAutoRefreshInSeconds, refreshedData.Tokens.ExpireInSeconds)
	assert.Greater(t, refreshedData.Tokens.NextAutoRefreshInSeconds, int64(1))

	assert.True(t, refreshedData.Tokens.RefreshCooldown)
	// 1 second < refresh cooldown <= minimum refresh interval
	assert.LessOrEqual(t, refreshedData.Tokens.RefreshCooldownSeconds, session.RefreshMinInterval)
	assert.Greater(t, refreshedData.Tokens.RefreshCooldownSeconds, int64(1))

	assert.True(t, data.Session.Active)
	assert.True(t, refreshedData.Session.Active)

	assert.True(t, data.Session.TimeoutAt.IsZero())
	assert.True(t, refreshedData.Session.TimeoutAt.IsZero())

	assert.Equal(t, int64(-1), data.Session.TimeoutInSeconds)
	assert.Equal(t, int64(-1), refreshedData.Session.TimeoutInSeconds)
}

func TestSessionRefresh_Disabled(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = false

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Second
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	resp := sessionRefresh(t, idp, rpClient)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSessionRefresh_WithInactivity(t *testing.T) {
	cfg := mock.Config()
	cfg.Session.Refresh = true
	cfg.Session.Inactivity = true
	cfg.Session.InactivityTimeout = 10 * time.Minute

	idp := mock.NewIdentityProvider(cfg)
	idp.ProviderHandler.TokenDuration = 5 * time.Second
	defer idp.Close()

	rpClient := idp.RelyingPartyClient()
	login(t, rpClient, idp)

	// get initial session info
	resp := sessionInfo(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var data session.MetadataVerboseWithRefresh
	err := json.Unmarshal([]byte(resp.Body), &data)
	assert.NoError(t, err)

	// wait until refresh cooldown has reached zero before refresh
	waitForRefreshCooldownTimer(t, idp, rpClient)

	resp = sessionRefresh(t, idp, rpClient)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var refreshedData session.MetadataVerboseWithRefresh
	err = json.Unmarshal([]byte(resp.Body), &refreshedData)
	assert.NoError(t, err)

	maxDelta := 5 * time.Second

	assert.True(t, data.Session.Active)
	assert.True(t, refreshedData.Session.Active)

	assert.False(t, data.Session.TimeoutAt.IsZero())
	assert.False(t, refreshedData.Session.TimeoutAt.IsZero())

	expectedTimeoutAt := time.Now().Add(cfg.Session.InactivityTimeout)
	assert.WithinDuration(t, expectedTimeoutAt, data.Session.TimeoutAt, maxDelta)
	assert.WithinDuration(t, expectedTimeoutAt, refreshedData.Session.TimeoutAt, maxDelta)

	assert.True(t, refreshedData.Session.TimeoutAt.After(data.Session.TimeoutAt))

	previousTimeoutDuration := time.Duration(data.Session.TimeoutInSeconds) * time.Second
	assert.WithinDuration(t, expectedTimeoutAt, time.Now().Add(previousTimeoutDuration), maxDelta)

	refreshedTimeoutDuration := time.Duration(refreshedData.Session.TimeoutInSeconds) * time.Second
	assert.WithinDuration(t, expectedTimeoutAt, time.Now().Add(refreshedTimeoutDuration), maxDelta)
}
