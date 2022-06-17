package session_test

import (
	"net/url"
	"testing"
	"time"

	jwtlib "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/session"
)

func TestSessionID(t *testing.T) {
	for _, test := range []struct {
		name       string
		config     *openid.Configuration
		idToken    *jwt.IDToken
		params     url.Values
		want       string
		exactMatch bool
		expectErr  bool
	}{
		{
			name:       "Support for front channel session with required sid claim",
			config:     sidRequired(),
			idToken:    idTokenWithSid("some-sid"),
			want:       "some-sid",
			exactMatch: true,
		},
		{
			name:       "Support for front channel session with required sid claim and session_state in param",
			config:     sidRequired(),
			params:     params("session_state", "some-session-state"),
			idToken:    idTokenWithSid("some-sid"),
			want:       "some-sid",
			exactMatch: true,
		},
		{
			name:      "Support for front channel session without required sid claim",
			config:    sidRequired(),
			idToken:   idToken(),
			expectErr: true,
		},
		{
			name:       "Support for session management with required param",
			config:     sessionStateRequired(),
			idToken:    idToken(),
			params:     params("session_state", "some-session"),
			want:       "some-session",
			exactMatch: true,
		},
		{
			name:       "Support for session management with required param and sid in id_token",
			config:     sessionStateRequired(),
			idToken:    idTokenWithSid("some-sid"),
			params:     params("session_state", "some-session"),
			want:       "some-sid",
			exactMatch: true,
		},
		{
			name:      "Support for session management with missing required param",
			config:    sessionStateRequired(),
			idToken:   idToken(),
			params:    params("not_session_state", "some-session"),
			expectErr: true,
		},
		{
			name:       "No support for front-channel logout nor session management should generate session ID",
			config:     &openid.Configuration{},
			idToken:    idToken(),
			want:       "some-generated-id",
			exactMatch: false,
		},
		{
			name:       "No support for front-channel logout nor session management, sid in id_token",
			config:     &openid.Configuration{},
			idToken:    idTokenWithSid("some-sid"),
			want:       "some-sid",
			exactMatch: true,
		},
		{
			name:       "No support for front-channel logout nor session management, session_state in param",
			config:     &openid.Configuration{},
			idToken:    idToken(),
			params:     params("session_state", "some-session-state"),
			want:       "some-session-state",
			exactMatch: true,
		},
		{
			name:       "No support for front-channel logout nor session management, sid in id_token and session_state in param, sid should take precedence",
			config:     &openid.Configuration{},
			idToken:    idTokenWithSid("some-sid"),
			params:     params("session_state", "some-session-state"),
			want:       "some-sid",
			exactMatch: true,
		},
	} {
		actual, err := session.NewSessionID(test.config, test.idToken, test.params)

		t.Run(test.name, func(t *testing.T) {
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if test.exactMatch {
					assert.Equal(t, test.want, actual)
				}

				assert.NotEmpty(t, actual)
			}
		})
	}
}

func sidRequired() *openid.Configuration {
	return &openid.Configuration{
		FrontchannelLogoutSessionSupported: true,
		FrontchannelLogoutSupported:        true,
	}
}

func sessionStateRequired() *openid.Configuration {
	return &openid.Configuration{
		CheckSessionIframe: "https://some-provider/some-endpoint",
	}
}

func params(key, value string) url.Values {
	values := url.Values{}
	if len(key) > 0 && len(value) > 0 {
		values.Add(key, value)
	}
	return values
}

func newIDToken(extraClaims map[string]string) *jwt.IDToken {
	idToken := jwtlib.New()
	idToken.Set("sub", "test")
	idToken.Set("iss", "test")
	idToken.Set("aud", "test")
	idToken.Set("iat", time.Now().Unix())
	idToken.Set("exp", time.Now().Add(time.Hour).Unix())

	for claim, value := range extraClaims {
		if len(claim) > 0 {
			idToken.Set(claim, value)
		}
	}

	serialized, err := jwtlib.NewSerializer().Serialize(idToken)
	if err != nil {
		panic(err)
	}

	return jwt.NewIDToken(string(serialized), idToken)
}

func idTokenWithSid(sid string) *jwt.IDToken {
	return newIDToken(map[string]string{
		"sid": sid,
	})
}

func idToken() *jwt.IDToken {
	return newIDToken(nil)
}
