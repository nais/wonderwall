package client_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid/client"
)

func TestLogoutBackChannel(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	unknownKeys, err := crypto.NewJwkSet()
	require.NoError(t, err)

	cfg := mock.Config()
	cfg.OpenID.Audiences = []string{"trusted-id-1"}
	cfg.OpenID.ClientID = "some-client-id"
	openidCfg := mock.NewTestConfiguration(cfg)
	openidCfg.TestProvider.SetIssuer("https://some-issuer")
	jwksProvider := mock.NewTestJwksProvider()
	c, err := client.NewClient(openidCfg, jwksProvider)
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		mutate      func(tok jwt.Token)
		signingKeys *crypto.JwkSet
		expectErr   string
		expectSid   string
	}{
		{
			name:      "valid with sid and sub",
			expectSid: "some-sid",
		},
		{
			name: "sub only",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("sid")
			},
			expectErr: `missing or invalid "sid" claim`,
		},
		{
			name: "valid with sid only",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("sub")
			},
			expectSid: "some-sid",
		},
		{
			name: "valid with trusted additional audience",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", []string{"some-client-id", "trusted-id-1"})
			},
			expectSid: "some-sid",
		},
		{
			name: "empty sid",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("sid", "")
			},
			expectErr: `missing or invalid "sid" claim`,
		},
		{
			name: "non-string sid",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("sid", 123)
			},
			expectErr: `missing or invalid "sid" claim`,
		},
		{
			name: "nonce present",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("nonce", "some-nonce")
			},
			expectErr: `must not contain a "nonce" claim`,
		},
		{
			name: "missing events",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("events")
			},
			expectErr: `missing or malformed "events" claim`,
		},
		{
			name: "events without back-channel logout event",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("events", map[string]any{"some-other-event": map[string]any{}})
			},
			expectErr: `does not contain "http://schemas.openid.net/event/backchannel-logout"`,
		},
		{
			name: "back-channel logout event is not an object",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("events", map[string]any{client.BackChannelLogoutEvent: "not-an-object"})
			},
			expectErr: "event value must be a JSON object",
		},
		{
			name: "missing jti",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("jti")
			},
			expectErr: `required claim "jti"`,
		},
		{
			name: "missing iat",
			mutate: func(tok jwt.Token) {
				_ = tok.Remove("iat")
			},
			expectErr: `required claim "iat"`,
		},
		{
			name: "iat too old",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("iat", now.Add(-5*time.Minute-time.Minute).Unix())
				_ = tok.Remove("exp")
			},
			expectErr: "iat",
		},
		{
			name: "iat in the future",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("iat", now.Add(time.Minute).Unix())
			},
			expectErr: `"iat" not satisfied`,
		},
		{
			name: "expired",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("exp", now.Add(-time.Minute).Unix())
			},
			expectErr: `"exp" not satisfied`,
		},
		{
			name: "wrong issuer",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("iss", "https://some-other-issuer")
			},
			expectErr: `"iss" not satisfied`,
		},
		{
			name: "wrong audience",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", "some-other-client-id")
			},
			expectErr: `"aud" not satisfied`,
		},
		{
			name: "untrusted additional audience",
			mutate: func(tok jwt.Token) {
				_ = tok.Set("aud", []string{"some-client-id", "untrusted-id"})
			},
			expectErr: "untrusted audience(s) found",
		},
		{
			name:        "unknown signing key",
			signingKeys: unknownKeys,
			expectErr:   "verifying signature",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			keys := jwksProvider.JwksPair
			if tt.signingKeys != nil {
				keys = tt.signingKeys
			}
			body := url.Values{"logout_token": {makeLogoutToken(t, now, keys, tt.mutate)}}
			r := httptest.NewRequest(http.MethodPost, "/oauth2/logout/backchannel", strings.NewReader(body.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			sid, err := c.LogoutBackChannel(httptest.NewRecorder(), r)
			if tt.expectErr != "" {
				assert.ErrorIs(t, err, client.ErrLogoutBackChannelInvalidToken)
				assert.ErrorContains(t, err, tt.expectErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectSid, sid)
		})
	}
}

func makeLogoutToken(t *testing.T, now time.Time, keys *crypto.JwkSet, mutate func(tok jwt.Token)) string {
	t.Helper()

	tok := jwt.New()
	_ = tok.Set("iss", "https://some-issuer")
	_ = tok.Set("aud", "some-client-id")
	_ = tok.Set("sub", "some-sub")
	_ = tok.Set("sid", "some-sid")
	_ = tok.Set("iat", now.Unix())
	_ = tok.Set("exp", now.Add(2*time.Minute).Unix())
	_ = tok.Set("jti", "some-jti")
	_ = tok.Set("events", map[string]any{client.BackChannelLogoutEvent: map[string]any{}})

	if mutate != nil {
		mutate(tok)
	}

	key, ok := keys.Private.Key(0)
	require.True(t, ok)
	alg, ok := key.Algorithm()
	require.True(t, ok)

	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	require.NoError(t, err)
	return string(signed)
}
