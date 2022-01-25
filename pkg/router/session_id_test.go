package router_test

import (
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router"
)

func TestSessionID(t *testing.T) {
	for _, test := range []struct {
		name       string
		config     *openid.Configuration
		idToken    *openid.IDToken
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
			name:      "Support for front channel session without required sid claim",
			config:    sidRequired(),
			idToken:   idTokenWithSid(""),
			expectErr: true,
		},
		{
			name:       "Support for session management with required param",
			config:     sessionStateRequired(),
			params:     params("session_state", "some-session"),
			want:       "some-session",
			exactMatch: true,
		},
		{
			name:      "Support for session management with missing required param",
			config:    sessionStateRequired(),
			params:    params("not_session_state", "some-session"),
			expectErr: true,
		},
		{
			name:   "No support for front-channel logout nor session management",
			config: &openid.Configuration{},
			want:   "some-session",
		},
	} {
		actual, err := router.SessionID(test.config, test.idToken, test.params)

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

func idTokenWithSid(sid string) *openid.IDToken {
	idToken := jwt.New()
	if len(sid) > 0 {
		idToken.Set("sid", sid)
	}
	serialized, err := jwt.NewSerializer().Serialize(idToken)
	if err != nil {
		panic(err)
	}

	return &openid.IDToken{
		Raw:   string(serialized),
		Token: idToken,
	}
}
