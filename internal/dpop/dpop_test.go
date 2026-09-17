package dpop

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProofer(t *testing.T) {
	proofer := testProofer(t)
	target, err := url.Parse("https://example.test/a%2Fb/c?q=1#fragment")
	require.NoError(t, err)

	t.Run("required claims and signature", func(t *testing.T) {
		encoded, err := proofer.Proof(t.Context(), http.MethodGet, target, "", "")
		require.NoError(t, err)

		publicKey, err := proofer.key.PublicKey()
		require.NoError(t, err)

		token, err := jwt.Parse(encoded, jwt.WithKey(jwa.RS256(), publicKey))
		require.NoError(t, err)

		assert.True(t, token.Has("htm"))
		assert.True(t, token.Has("htu"))

		jti, ok := token.JwtID()
		require.True(t, ok)
		assert.NotEmpty(t, jti)

		issued, ok := token.IssuedAt()
		require.True(t, ok)
		assert.LessOrEqual(t, time.Since(issued), time.Second)
	})

	t.Run("method and target normalization", func(t *testing.T) {
		encoded, err := proofer.Proof(t.Context(), "get", target, "", "")
		require.NoError(t, err)

		proof := parseInsecure(t, encoded)

		var method, targetURI string
		require.NoError(t, proof.Get("htm", &method))
		require.NoError(t, proof.Get("htu", &targetURI))
		assert.Equal(t, http.MethodGet, method)
		assert.Equal(t, "https://example.test/a%2Fb/c", targetURI)
	})

	t.Run("nonce and access-token hash", func(t *testing.T) {
		encoded, err := proofer.Proof(t.Context(), http.MethodPost, target, "nonce", "access-token")
		require.NoError(t, err)

		proof := parseInsecure(t, encoded)

		var nonce, ath string
		require.NoError(t, proof.Get("nonce", &nonce))
		require.NoError(t, proof.Get("ath", &ath))
		assert.Equal(t, "nonce", nonce)

		hash := sha256.Sum256([]byte("access-token"))
		assert.Equal(t, base64.RawURLEncoding.EncodeToString(hash[:]), ath)

		decoded, err := base64.RawURLEncoding.DecodeString(ath)
		require.NoError(t, err)
		assert.Len(t, decoded, sha256.Size)
	})

	t.Run("omitted empty optional claims", func(t *testing.T) {
		encoded, err := proofer.Proof(t.Context(), http.MethodPost, target, "", "")
		require.NoError(t, err)

		proof := parseInsecure(t, encoded)
		assert.False(t, proof.Has("nonce"))
		assert.False(t, proof.Has("ath"))
		assert.False(t, proof.Has("exp"))
	})

	t.Run("fresh JTI", func(t *testing.T) {
		one, err := proofer.Proof(t.Context(), http.MethodPost, target, "", "")
		require.NoError(t, err)

		two, err := proofer.Proof(t.Context(), http.MethodPost, target, "", "")
		require.NoError(t, err)

		firstJTI, ok := parseInsecure(t, one).JwtID()
		require.True(t, ok)

		secondJTI, ok := parseInsecure(t, two).JwtID()
		require.True(t, ok)
		assert.NotEqual(t, firstJTI, secondJTI)
	})

	t.Run("protected public-key headers and thumbprint", func(t *testing.T) {
		encoded, err := proofer.Proof(t.Context(), http.MethodGet, target, "", "")
		require.NoError(t, err)

		headerPart := bytes.SplitN(encoded, []byte("."), 2)[0]
		var header struct {
			Typ string          `json:"typ"`
			Alg string          `json:"alg"`
			JWK json.RawMessage `json:"jwk"`
		}
		decodedHeader, err := base64.RawURLEncoding.DecodeString(string(headerPart))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(decodedHeader, &header))
		assert.Equal(t, proofType, header.Typ)
		assert.Equal(t, jwa.RS256().String(), header.Alg)
		assert.NotEmpty(t, header.JWK)
		assert.NotContains(t, string(header.JWK), `"d"`)
		assert.NotEmpty(t, proofer.Thumbprint())
	})
}

func TestTransport(t *testing.T) {
	proofer := testProofer(t)
	tokenEndpoint := "https://example.test/token"

	t.Run("matches token endpoint", func(t *testing.T) {
		tests := []struct {
			name            string
			configuredURL   string
			requestURL      string
			wantProof       bool
			wantProofTarget string
		}{
			{
				name:            "exact endpoint",
				configuredURL:   tokenEndpoint,
				requestURL:      tokenEndpoint,
				wantProof:       true,
				wantProofTarget: tokenEndpoint,
			},
			{
				name:            "equivalent host and default port",
				configuredURL:   "https://EXAMPLE.TEST:443/token",
				requestURL:      tokenEndpoint,
				wantProof:       true,
				wantProofTarget: tokenEndpoint,
			},
			{
				name:          "different path",
				configuredURL: tokenEndpoint,
				requestURL:    "https://example.test/other",
				wantProof:     false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var proofTarget string
				var proofAttached bool
				base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
					if encoded := request.Header.Get(proofHeader); encoded != "" {
						proofAttached = true
						proof := parseInsecure(t, []byte(encoded))
						require.NoError(t, proof.Get("htu", &proofTarget))
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
				})
				transport, err := NewTransport(base, tt.configuredURL, proofer)
				require.NoError(t, err)

				request, err := http.NewRequest(http.MethodPost, tt.requestURL, strings.NewReader("body"))
				require.NoError(t, err)

				response, err := transport.RoundTrip(request)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, response.StatusCode)
				assert.Equal(t, tt.wantProof, proofAttached)

				if tt.wantProof {
					assert.Equal(t, tt.wantProofTarget, proofTarget)
				}
			})
		}
	})

	t.Run("captures nonce from responses without retrying", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			statusCode int
			body       string
		}{
			{
				name:       "nonce challenge",
				statusCode: http.StatusBadRequest,
				body:       `{"error":"use_dpop_nonce"}`,
			},
			{
				name:       "successful response",
				statusCode: http.StatusOK,
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				var requests int
				var proofs []jwt.Token

				base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					proofs = append(proofs, parseInsecure(t, []byte(request.Header.Get(proofHeader))))

					header := make(http.Header)
					if requests == 1 {
						header.Set(nonceHeader, "nonce-1")
					}

					return &http.Response{
						StatusCode: test.statusCode,
						Header:     header,
						Body:       io.NopCloser(strings.NewReader(test.body)),
					}, nil
				})
				transport, err := NewTransport(base, tokenEndpoint, proofer)
				require.NoError(t, err)

				for range 2 {
					request, err := http.NewRequest(http.MethodPost, tokenEndpoint, nil)
					require.NoError(t, err)

					response, err := transport.RoundTrip(request)
					require.NoError(t, err)
					assert.Equal(t, test.statusCode, response.StatusCode)
				}

				assert.Equal(t, 2, requests)
				require.Len(t, proofs, 2)
				assert.False(t, proofs[0].Has("nonce"))

				var nonce string
				require.NoError(t, proofs[1].Get("nonce", &nonce))
				assert.Equal(t, "nonce-1", nonce)
			})
		}
	})

	t.Run("does not mutate the original request", func(t *testing.T) {
		base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
			assert.NotEmpty(t, request.Header.Get(proofHeader))
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
		})

		transport, err := NewTransport(base, tokenEndpoint, proofer)
		require.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader("body"))
		require.NoError(t, err)

		request.Header.Set("X-Test", "unchanged")
		originalURL := request.URL.String()
		originalProof := request.Header.Get(proofHeader)

		_, err = transport.RoundTrip(request)
		require.NoError(t, err)
		assert.Equal(t, originalURL, request.URL.String())
		assert.Equal(t, originalProof, request.Header.Get(proofHeader))
		assert.Equal(t, "unchanged", request.Header.Get("X-Test"))
	})
}

func TestTransportNonceConcurrentAccess(t *testing.T) {
	proofer := testProofer(t)
	transport, err := NewTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		header := http.Header{}
		header.Set(nonceHeader, "nonce")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     header,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
		}, nil
	}), "https://example.test/token", proofer)
	require.NoError(t, err)

	var wait sync.WaitGroup
	for range 10 {
		wait.Go(func() {
			request, _ := http.NewRequest(http.MethodPost, "https://example.test/token", nil)
			_, _ = transport.RoundTrip(request)
			_ = transport.nonceValue()
		})
	}
	wait.Wait()
}

func testProofer(t *testing.T) *Proofer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	private, err := jwk.Import(key)
	require.NoError(t, err)
	require.NoError(t, private.Set(jwk.AlgorithmKey, jwa.RS256()))

	proofer, err := NewProofer(private)
	require.NoError(t, err)

	return proofer
}

func parseInsecure(t *testing.T, encoded []byte) jwt.Token {
	t.Helper()

	token, err := jwt.ParseInsecure(encoded)
	require.NoError(t, err)

	return token
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
