package session

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
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

func TestManager_RefreshUpdatesRefreshToken(t *testing.T) {
	for _, test := range []struct {
		name                 string
		responseRefreshToken string
		wantRefreshToken     string
	}{
		{name: "preserves existing token when omitted", wantRefreshToken: "old-refresh-token"},
		{name: "replaces existing token when returned", responseRefreshToken: "new-refresh-token", wantRefreshToken: "new-refresh-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]any{
					"access_token": "new-access-token",
					"token_type":   openid.TokenTypeBearer,
					"expires_in":   60,
				}
				if test.responseRefreshToken != "" {
					response["refresh_token"] = test.responseRefreshToken
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			client, openidCfg := newTestClient(t, server.URL, false)
			manager := newTestManager(t, client, openidCfg)
			data := newTestData("")
			data.RefreshToken = "old-refresh-token"
			data.Metadata.Tokens.RefreshedAt = time.Now().Add(-time.Hour)
			sess := writeTestSession(t, manager.store, data)

			refreshed, err := manager.Refresh(newTestRequest(), sess)
			require.NoError(t, err)
			assert.Equal(t, test.wantRefreshToken, refreshed.data.RefreshToken)

			stored, err := manager.getForTicket(t.Context(), sess.ticket)
			require.NoError(t, err)
			assert.Equal(t, test.wantRefreshToken, stored.data.RefreshToken)
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

const (
	ingressA = "https://a.example.test"
	ingressB = "https://b.example.test/app"
	testSID  = "shared-provider-session"
)

func TestManager_SameSIDOnMultipleHosts(t *testing.T) {
	store := NewMemory()
	mgr := newIngressTestManager(t, store, false, ingressA, ingressB)

	sessA := createOnIngress(t, mgr, ingressA)
	sessB := createOnIngress(t, mgr, ingressB)

	assert.Equal(t, fmt.Sprintf("test:client-id:%s:%x", testSID, sha256.Sum256([]byte("a.example.test"))), sessA.key())
	assert.NotEqual(t, sessA.key(), sessB.key())
	assert.Equal(t, testSID, sessA.ExternalSessionID())
	assert.Equal(t, testSID, sessB.ExternalSessionID())
	requireReadable(t, mgr, sessA)
	requireReadable(t, mgr, sessB)

	require.NoError(t, mgr.Delete(t.Context(), sessA))
	requireDeleted(t, mgr, sessA)
	requireReadable(t, mgr, sessB)
}

func TestManager_DeleteForExternalIDDeletesAllHostSessions(t *testing.T) {
	for _, test := range []struct {
		name              string
		ingressesAtLogout []string
	}{
		{name: "unchanged ingresses", ingressesAtLogout: []string{ingressA, ingressB}},
		{name: "path removed from remaining host", ingressesAtLogout: []string{ingressA, "https://b.example.test"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemory()
			mgr := newIngressTestManager(t, store, false, ingressA, ingressB)
			sessA := createOnIngress(t, mgr, ingressA)
			sessB := createOnIngress(t, mgr, ingressB)

			legacy := newIngressTestManager(t, store, false, ingressA)
			sessLegacy := createOnIngress(t, legacy, ingressA)

			logout := newIngressTestManager(t, store, false, test.ingressesAtLogout...)
			require.NoError(t, logout.DeleteForExternalID(t.Context(), testSID))

			requireDeleted(t, mgr, sessA)
			requireDeleted(t, mgr, sessB)
			requireDeleted(t, legacy, sessLegacy)
		})
	}
}

func TestManager_DeleteForExternalIDAfterReducingToSingleHost(t *testing.T) {
	store := NewMemory()
	mgr := newIngressTestManager(t, store, false, ingressA, ingressB)
	sess := createOnIngress(t, mgr, ingressA)

	single := newIngressTestManager(t, store, false, ingressA)
	require.NoError(t, single.DeleteForExternalID(t.Context(), testSID))

	requireDeleted(t, mgr, sess)
}

func TestManager_LegacyKey(t *testing.T) {
	for _, test := range []struct {
		name      string
		sso       bool
		ingresses []string
	}{
		// Paths share a single host.
		{name: "standalone with single host", ingresses: []string{ingressA, ingressA + "/other"}},
		{name: "sso with multiple hosts", sso: true, ingresses: []string{ingressA, ingressB}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := NewMemory()
			mgr := newIngressTestManager(t, store, test.sso, test.ingresses...)

			sess := createOnIngress(t, mgr, ingressA)
			assert.Equal(t, "test:client-id:"+testSID, sess.key())

			require.NoError(t, mgr.DeleteForExternalID(t.Context(), testSID))
			requireDeleted(t, mgr, sess)
		})
	}
}

func TestManager_MultipleHostsRequiresMatchingIngress(t *testing.T) {
	store := NewMemory()
	mgr := newIngressTestManager(t, store, false, ingressA, ingressB)

	_, err := mgr.Create(newTestRequest(), newIngressTestTokens(t), time.Hour)

	require.Error(t, err)
	assert.Empty(t, store.(*memorySessionStore).sessions)
}

func newIngressTestManager(t *testing.T, store Store, sso bool, ingresses ...string) *manager {
	t.Helper()
	client, openidCfg := newTestClient(t, "https://provider.example/token", false)

	cfg := &config.Config{Ingresses: ingresses}
	cfg.OpenID.Provider = "test"
	cfg.SSO.Enabled = sso
	parsed, err := ingress.ParseIngresses(cfg)
	require.NoError(t, err)
	m, err := NewManager(cfg, openidCfg, crypto.NewCrypter(make([]byte, crypto.KeySize)), client, parsed)
	require.NoError(t, err)

	mgr := m.(*manager)
	mgr.store = store
	mgr.reader.store = store
	return mgr
}

func createOnIngress(t *testing.T, mgr *manager, rawIngress string) *Session {
	t.Helper()
	ing, err := ingress.ParseIngress(rawIngress)
	require.NoError(t, err)

	r := mw.RequestWithIngress(httptest.NewRequest(http.MethodGet, rawIngress+"/oauth2/callback", nil), *ing)
	sess, err := mgr.Create(r, newIngressTestTokens(t), time.Hour)
	require.NoError(t, err)
	return sess
}

func newIngressTestTokens(t *testing.T) *openid.Tokens {
	t.Helper()
	claims := jwt.New()
	require.NoError(t, claims.Set("sid", testSID))
	return &openid.Tokens{
		AccessToken: "access-token",
		Expiry:      time.Now().Add(time.Hour),
		IDToken:     openid.NewIDToken("id-token", claims),
		TokenType:   openid.TokenTypeBearer,
	}
}

func requireReadable(t *testing.T, mgr *manager, sess *Session) {
	t.Helper()
	_, err := mgr.getForTicket(t.Context(), sess.ticket)
	require.NoError(t, err)
}

func requireDeleted(t *testing.T, mgr *manager, sess *Session) {
	t.Helper()
	_, err := mgr.getForTicket(t.Context(), sess.ticket)
	require.ErrorIs(t, err, ErrNotFound)
}
