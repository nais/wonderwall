package session_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jwtlib "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/mock"
	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/session"
)

func TestExternalID(t *testing.T) {
	for _, test := range []struct {
		name       string
		config     openidconfig.Provider
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
			config:     standardConfig(),
			idToken:    idToken(),
			want:       "some-generated-id",
			exactMatch: false,
		},
		{
			name:       "No support for front-channel logout nor session management, sid in id_token",
			config:     standardConfig(),
			idToken:    idTokenWithSid("some-sid"),
			want:       "some-sid",
			exactMatch: true,
		},
		{
			name:       "No support for front-channel logout nor session management, session_state in param",
			config:     standardConfig(),
			idToken:    idToken(),
			params:     params("session_state", "some-session-state"),
			want:       "some-session-state",
			exactMatch: true,
		},
		{
			name:       "No support for front-channel logout nor session management, sid in id_token and session_state in param, sid should take precedence",
			config:     standardConfig(),
			idToken:    idTokenWithSid("some-sid"),
			params:     params("session_state", "some-session-state"),
			want:       "some-sid",
			exactMatch: true,
		},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://wonderwall/callback", nil)

		if test.params != nil {
			req.URL.RawQuery = test.params.Encode()
		}

		actual, err := session.ExternalID(req, test.config, test.idToken)

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

func testConfiguration() *mock.TestConfiguration {
	idp := mock.NewIdentityProvider(mock.Config())
	idp.Close() // we're not making any calls in these tests

	return idp.OpenIDConfig
}

func standardConfig() openidconfig.Provider {
	return testConfiguration().Provider()
}

func sidRequired() openidconfig.Provider {
	cfg := testConfiguration()
	cfg.TestProvider.WithFrontChannelLogoutSupport()

	return cfg.Provider()
}

func sessionStateRequired() openidconfig.Provider {
	endpoint := "https://some-provider/some-endpoint"

	cfg := testConfiguration()
	cfg.TestProvider.WithCheckSessionIFrameSupport(endpoint)

	return cfg.Provider()
}

func params(key, value string) url.Values {
	values := url.Values{}
	if len(key) > 0 && len(value) > 0 {
		values.Add(key, value)
	}
	return values
}

func newIDToken(extraClaims map[string]string) *openid.IDToken {
	now := time.Now().Truncate(time.Second)

	idToken := jwtlib.New()
	idToken.Set("sub", "test")
	idToken.Set("iss", "test")
	idToken.Set("aud", "test")
	idToken.Set("iat", now.Unix())
	idToken.Set("exp", now.Add(time.Hour).Unix())

	for claim, value := range extraClaims {
		if len(claim) > 0 {
			idToken.Set(claim, value)
		}
	}

	serialized, err := jwtlib.NewSerializer().Serialize(idToken)
	if err != nil {
		panic(err)
	}

	return openid.NewIDToken(string(serialized), idToken)
}

func idTokenWithSid(sid string) *openid.IDToken {
	return newIDToken(map[string]string{
		"sid": sid,
	})
}

func idToken() *openid.IDToken {
	return newIDToken(nil)
}
