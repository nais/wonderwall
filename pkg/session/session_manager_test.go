package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		{
			name:       "session bound to current key",
			client:     client,
			thumbprint: client.DPoPThumbprint(),
		},
		{
			name:        "session bound to rotated key",
			client:      client,
			thumbprint:  rotated.DPoPThumbprint(),
			wantInvalid: true,
		},
		{
			name:        "legacy bearer session with DPoP enabled",
			client:      client,
			wantInvalid: true,
		},
		{
			name:        "DPoP-bound session with DPoP disabled",
			client:      bearerClient,
			thumbprint:  client.DPoPThumbprint(),
			wantInvalid: true,
		},
		{name: "bearer session with DPoP disabled", client: bearerClient},
		{name: "bearer session in SSO proxy"},
		{
			name:        "DPoP-bound session in SSO proxy",
			thumbprint:  client.DPoPThumbprint(),
			wantInvalid: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemory()
			rd := &reader{cfg: &config.Config{}, client: test.client, store: store}
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

func TestManager_RefreshPreservesDPoPBinding(t *testing.T) {
	for _, test := range []struct {
		name       string
		enableDPoP bool
		tokenType  string
	}{
		{name: "Bearer", tokenType: openid.TokenTypeBearer},
		{name: "DPoP", enableDPoP: true, tokenType: openid.TokenTypeDPoP},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token":  "new-access-token",
					"refresh_token": "new-refresh-token",
					"token_type":    test.tokenType,
					"expires_in":    60,
				})
			}))
			defer server.Close()

			client, openidCfg := newTestClient(t, server.URL, test.enableDPoP)
			mgr := newTestManager(t, client, openidCfg)

			data := newTestData(client.DPoPThumbprint())
			data.RefreshToken = "refresh-token"
			data.Metadata.Tokens.RefreshedAt = time.Now().Add(-time.Hour)

			sess := writeTestSession(t, mgr.store, data)

			refreshed, err := mgr.Refresh(newTestRequest(), sess)
			require.NoError(t, err)
			assert.Equal(t, 1, requests)
			assert.Equal(t, "new-access-token", refreshed.data.AccessToken)
			assert.Equal(t, client.DPoPThumbprint(), refreshed.data.DPoPThumbprint)

			stored, err := mgr.getForTicket(t.Context(), refreshed.ticket)
			require.NoError(t, err)
			assert.Equal(t, "new-access-token", stored.data.AccessToken)
			assert.Equal(t, client.DPoPThumbprint(), stored.data.DPoPThumbprint)
		})
	}
}

func TestManager_RefreshInvalidatesSessionOnTokenTypeMismatch(t *testing.T) {
	for _, test := range []struct {
		name       string
		enableDPoP bool
		tokenType  string
	}{
		{name: "Bearer response in DPoP mode", enableDPoP: true, tokenType: openid.TokenTypeBearer},
		{name: "DPoP response in Bearer mode", tokenType: openid.TokenTypeDPoP},
		{name: "unsupported response", tokenType: "Basic"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "new-access-token",
					"token_type":   test.tokenType,
					"expires_in":   60,
				})
			}))
			defer server.Close()

			client, openidCfg := newTestClient(t, server.URL, test.enableDPoP)
			mgr := newTestManager(t, client, openidCfg)

			data := newTestData(client.DPoPThumbprint())
			data.RefreshToken = "refresh-token"
			data.Metadata.Tokens.RefreshedAt = time.Now().Add(-time.Hour)
			sess := writeTestSession(t, mgr.store, data)

			_, err := mgr.Refresh(newTestRequest(), sess)
			require.ErrorIs(t, err, ErrInvalid)
			require.ErrorIs(t, err, openid.ErrTokenTypeMismatch)
		})
	}
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
			DPoP:            enableDPoP,
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
		reader:    &reader{cfg: cfg, client: client, store: store},
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

func newTestRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://wonderwall.example/callback", nil)
}
