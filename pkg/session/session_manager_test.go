package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtlib "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

func TestReader_ValidatesDPoPBinding(t *testing.T) {
	client, _ := newTestClient(t, "https://provider.example/token", true)
	rotated, _ := newTestClient(t, "https://provider.example/token", true)
	bearerClient, _ := newTestClient(t, "https://provider.example/token", false)

	for _, test := range []struct {
		name        string
		client      *openidclient.Client
		thumbprint  string
		wantInvalid bool
	}{
		{name: "session bound to current key", client: client, thumbprint: client.DPoPThumbprint()},
		{name: "session bound to rotated key", client: client, thumbprint: rotated.DPoPThumbprint(), wantInvalid: true},
		{name: "DPoP-bound session with DPoP disabled", client: bearerClient, thumbprint: client.DPoPThumbprint(), wantInvalid: true},
		{name: "bearer session", client: client},
		{name: "SSO proxy skips DPoP validation", thumbprint: client.DPoPThumbprint()},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemory()
			rd := &reader{cfg: &config.Config{}, cookieCrypter: newTestCrypter(t), client: test.client, store: store}
			sess := writeTestSession(t, store, newTestData(test.thumbprint))

			_, err := rd.getForTicket(t.Context(), sess.ticket)

			if test.wantInvalid {
				require.ErrorIs(t, err, ErrInvalid)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestManager_CreateBindsDPoPSession(t *testing.T) {
	for _, test := range []struct {
		name      string
		tokenType string
		wantDPoP  bool
	}{
		{name: "DPoP response", tokenType: openid.TokenTypeDPoP, wantDPoP: true},
		{name: "Bearer response", tokenType: openid.TokenTypeBearer},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, openidCfg := newTestClient(t, "https://provider.example/token", true)
			tokens := &openid.Tokens{
				AccessToken: "access-token",
				Expiry:      time.Now().Add(time.Hour),
				IDToken:     newTestIDToken(t),
				TokenType:   test.tokenType,
			}

			sess, err := newTestManager(t, client, openidCfg).Create(newTestRequest(), tokens, time.Hour)
			require.NoError(t, err)

			assert.Equal(t, test.wantDPoP, sess.UsesDPoP())
			if test.wantDPoP {
				assert.Equal(t, client.DPoPThumbprint(), sess.data.DPoPThumbprint)
			}
		})
	}
}

func TestManager_CreateRejectsDPoPWhileInactive(t *testing.T) {
	client, openidCfg := newTestClient(t, "https://provider.example/token", false)
	tokens := &openid.Tokens{
		AccessToken: "access-token",
		Expiry:      time.Now().Add(time.Hour),
		IDToken:     newTestIDToken(t),
		TokenType:   openid.TokenTypeDPoP,
	}

	_, err := newTestManager(t, client, openidCfg).Create(newTestRequest(), tokens, time.Hour)
	require.ErrorIs(t, err, errUnexpectedDPoPTokenType)
}

func TestManager_RefreshUpdatesDPoPBinding(t *testing.T) {
	for _, test := range []struct {
		name      string
		tokenType string
		wantBound bool
	}{
		{name: "keeps binding", tokenType: openid.TokenTypeDPoP, wantBound: true},
		// RFC 9449, section 5 permits the provider to answer any token request with a bearer token.
		{name: "clears binding on downgrade", tokenType: openid.TokenTypeBearer},
		{name: "clears binding when omitted", wantBound: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "new-access-token",
					"refresh_token": "new-refresh-token",
					"token_type":    test.tokenType,
					"expires_in":    60,
				})
			}))
			defer server.Close()

			client, openidCfg := newTestClient(t, server.URL, true)
			manager := newTestManager(t, client, openidCfg)
			data := newTestData(client.DPoPThumbprint())
			data.RefreshToken = "refresh-token"
			data.Metadata.Tokens.RefreshedAt = time.Now().Add(-time.Hour)
			sess := writeTestSession(t, manager.store, data)

			refreshed, err := manager.Refresh(newTestRequest(), sess)
			require.NoError(t, err)

			assert.Equal(t, test.wantBound, refreshed.UsesDPoP())
			if test.wantBound {
				assert.Equal(t, client.DPoPThumbprint(), refreshed.data.DPoPThumbprint)
			}

			stored, err := manager.getForTicket(t.Context(), refreshed.ticket)
			require.NoError(t, err)
			assert.Equal(t, test.wantBound, stored.UsesDPoP())
		})
	}
}

func TestManager_RefreshRejectsDPoPWhileInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access-token",
			"token_type":   openid.TokenTypeDPoP,
			"expires_in":   60,
		})
	}))
	defer server.Close()

	client, openidCfg := newTestClient(t, server.URL, false)
	manager := newTestManager(t, client, openidCfg)
	data := newTestData("")
	data.RefreshToken = "refresh-token"
	data.Metadata.Tokens.RefreshedAt = time.Now().Add(-time.Hour)
	sess := writeTestSession(t, manager.store, data)

	_, err := manager.Refresh(newTestRequest(), sess)
	require.ErrorIs(t, err, ErrInvalid)
	require.ErrorIs(t, err, errUnexpectedDPoPTokenType)
}

// newTestClient returns an OpenID client for a provider served from a stub well-known endpoint.
func newTestClient(t *testing.T, tokenEndpoint string, enableDPoP bool) (*openidclient.Client, openidconfig.Config) {
	t.Helper()
	key, err := crypto.NewJwk()
	require.NoError(t, err)
	alg, ok := key.Algorithm()
	require.True(t, ok)
	keyJSON, err := json.Marshal(key)
	require.NoError(t, err)

	metadata := openidconfig.ProviderMetadata{
		AuthorizationEndpoint:            "https://provider.example/authorize",
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		Issuer:                           "https://provider.example",
		JwksURI:                          "https://provider.example/jwks",
		TokenEndpoint:                    tokenEndpoint,
		TokenEndpointAuthSigningAlgValuesSupported: []string{alg.String()},
	}
	if enableDPoP {
		metadata.DPoPSigningAlgValuesSupported = openidconfig.Supported{alg.String()}
	}

	wellKnown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(metadata)
	}))
	t.Cleanup(wellKnown.Close)

	cfg := &config.Config{
		OpenID: config.OpenID{
			ClientID:        "client-id",
			ClientJWK:       string(keyJSON),
			JWKSFallbackAlg: "RS256",
			Provider:        "test",
			WellKnownURL:    wellKnown.URL,
		},
	}
	openidCfg, err := openidconfig.NewConfig(t.Context(), cfg)
	require.NoError(t, err)

	client, err := openidclient.NewClient(openidCfg, nil)
	require.NoError(t, err)
	return client, openidCfg
}

func newTestManager(t *testing.T, client *openidclient.Client, openidCfg openidconfig.Config) *manager {
	t.Helper()
	cfg := &config.Config{}
	store := NewMemory()
	return &manager{
		reader:    &reader{cfg: cfg, cookieCrypter: newTestCrypter(t), client: client, store: store},
		cfg:       cfg,
		client:    client,
		openidCfg: openidCfg,
		store:     store,
	}
}

func writeTestSession(t *testing.T, store Store, data *Data) *Session {
	t.Helper()
	ticket, err := NewTicket("session-key")
	require.NoError(t, err)
	encrypted, err := data.Encrypt(ticket.Crypter())
	require.NoError(t, err)
	require.NoError(t, store.Write(t.Context(), ticket.Key(), encrypted, time.Hour))
	return NewSession(data, ticket)
}

func newTestData(thumbprint string) *Data {
	return &Data{
		ExternalSessionID: "external-session-id",
		AccessToken:       "access-token",
		DPoPThumbprint:    thumbprint,
		Metadata:          *NewMetadata(time.Hour, time.Hour),
	}
}

func newTestCrypter(t *testing.T) crypto.Crypter {
	t.Helper()
	key, err := crypto.EncryptionKeyOrGenerate(&config.Config{})
	require.NoError(t, err)
	return crypto.NewCrypter(key)
}

func newTestRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://wonderwall.example/callback", nil)
}

func newTestIDToken(t *testing.T) *openid.IDToken {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	token := jwtlib.New()
	for claim, value := range map[string]any{
		"aud": "test",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"iss": "test",
		"sub": "test",
	} {
		require.NoError(t, token.Set(claim, value))
	}
	return openid.NewIDToken("some-id-token", token)
}
