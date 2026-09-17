package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/nais/wonderwall/internal/dpop"
	httpinternal "github.com/nais/wonderwall/internal/http"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/internal/retry"
	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	urlpkg "github.com/nais/wonderwall/pkg/url"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

func init() {
	jwt.Settings(jwt.WithFlattenAudience(true))
}

var (
	ErrOpenIDClient = errors.New("client error")
	ErrOpenIDServer = errors.New("server error")
)

const (
	DefaultClientAssertionLifetime = 5 * time.Second
)

type JwksProvider interface {
	GetPublicJwkSet(ctx context.Context) (*jwk.Set, error)
	RefreshPublicJwkSet(ctx context.Context) (*jwk.Set, error)
}

type Client struct {
	cfg          openidconfig.Config
	dpopProofer  *dpop.Proofer
	httpClient   *http.Client
	jwksProvider JwksProvider
	oauth2Config *oauth2.Config
}

func NewClient(cfg openidconfig.Config, jwksProvider JwksProvider) (*Client, error) {
	oauth2Config := &oauth2.Config{
		ClientID: cfg.Client().ClientID(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   cfg.Provider().AuthorizationEndpoint(),
			TokenURL:  cfg.Provider().TokenEndpoint(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
		Scopes: cfg.Client().Scopes(),
	}

	var proofer *dpop.Proofer
	transport := http.RoundTripper(httpinternal.Transport())
	alg := cfg.Client().ClientJWKAlgorithm()
	if alg != nil && cfg.Provider().DPoPSigningAlgValuesSupported().Contains(alg.String()) {
		var err error
		proofer, err = dpop.NewProofer(cfg.Client().ClientJWK())
		if err != nil {
			return nil, fmt.Errorf("creating DPoP proofer: %w", err)
		}
		dpopTransport, err := dpop.NewTransport(transport, cfg.Provider().TokenEndpoint(), proofer)
		if err != nil {
			return nil, fmt.Errorf("creating DPoP transport: %w", err)
		}
		transport = dpopTransport
	}

	httpClient := &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport,
		// requests to the token and pushed authorization endpoints carry client credentials,
		// so following a redirect would forward them to a host the provider did not advertise.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refusing to follow redirect to %q", req.URL.Redacted())
		},
	}

	return &Client{
		cfg:          cfg,
		dpopProofer:  proofer,
		httpClient:   httpClient,
		jwksProvider: jwksProvider,
		oauth2Config: oauth2Config,
	}, nil
}

func (c *Client) DPoPThumbprint() string {
	if c.dpopProofer == nil {
		return ""
	}
	return c.dpopProofer.Thumbprint()
}

func (c *Client) ValidateDPoPBinding(thumbprint string) error {
	if thumbprint == "" {
		return nil
	}
	current := c.DPoPThumbprint()
	if current == "" {
		return fmt.Errorf("DPoP is inactive")
	}
	if current != thumbprint {
		return fmt.Errorf("DPoP key changed")
	}
	return nil
}

func (c *Client) DPoPProof(ctx context.Context, method string, target *url.URL, nonce, accessToken string) (string, error) {
	if c.dpopProofer == nil {
		return "", fmt.Errorf("DPoP is inactive")
	}
	proof, err := c.dpopProofer.Proof(ctx, method, target, nonce, accessToken)
	return string(proof), err
}

func (c *Client) Logout(r *http.Request) (*Logout, error) {
	logout, err := NewLogout(c, r)
	if err != nil {
		return nil, fmt.Errorf("logout: %w", err)
	}

	return logout, nil
}

func (c *Client) LogoutCallback(r *http.Request, cookie *openid.LogoutCookie, validator urlpkg.Validator) *LogoutCallback {
	return NewLogoutCallback(c, r, cookie, validator)
}

func (c *Client) AuthCodeGrant(ctx context.Context, code, codeVerifier, redirectURI string) (*oauth2.Token, error) {
	ctx, span := otel.StartSpan(ctx, "Client.AuthCodeGrant")
	defer span.End()

	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	return retryNonceChallenge(span, func() (*oauth2.Token, error) {
		clientAuth, err := c.ClientAuthenticationParams()
		if err != nil {
			return nil, err
		}
		opts := openid.ExchangeAuthorizationCodeParams(c.cfg.Client().ClientID(), code, codeVerifier, redirectURI).
			With(clientAuth).
			AuthCodeOptions()
		return c.oauth2Config.Exchange(ctx, code, opts...)
	})
}

func (c *Client) RefreshGrant(ctx context.Context, refreshToken, previousIDToken, expectedAcr string) (*openid.TokenResponse, error) {
	ctx, span := otel.StartSpan(ctx, "Client.RefreshGrant")
	defer span.End()
	payload := openid.RefreshGrantParams(c.cfg.Client().ClientID(), refreshToken)

	endpoint := c.cfg.Provider().TokenEndpoint()
	body, err := retryNonceChallenge(span, func() ([]byte, error) {
		return c.oauthPost(ctx, endpoint, payload)
	})
	if err != nil {
		return nil, err
	}

	var tokenResponse openid.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, fmt.Errorf("unmarshalling token response: %w", err)
	}
	span.SetAttributes(attribute.Int64("oauth.token_expires_in_seconds", tokenResponse.ExpiresIn))
	if tokenResponse.ExpiresIn <= 0 {
		return nil, fmt.Errorf("invalid token response: expires_in must be greater than 0, got %d", tokenResponse.ExpiresIn)
	}

	// NewTokens normalizes authorization-code responses; refresh responses are decoded here.
	tokenResponse.TokenType, err = openid.NormalizeTokenType(tokenResponse.TokenType)
	if err != nil {
		return nil, err
	}
	c.recordTokenType(span, tokenResponse.TokenType)

	// id_tokens may not always be returned from a refresh grant (OpenID Connect Core 12.1)
	if tokenResponse.IDToken != "" {
		jwkSet, err := c.jwksProvider.GetPublicJwkSet(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting jwks: %w", err)
		}

		err = openid.ValidateRefreshedIDToken(c.cfg, previousIDToken, tokenResponse.IDToken, expectedAcr, jwkSet)
		if err != nil {
			span.SetAttributes(attribute.Bool("oauth.valid_id_token", false))
			otel.AddErrorEvent(span, "refreshGrantError", "invalidIDToken", err)
			if errors.Is(err, jws.VerificationError()) {
				// JWKS might not be up to date, so we'll want to force a refresh for the next attempt
				_, _ = c.jwksProvider.RefreshPublicJwkSet(ctx)
				return nil, retry.RetryableError(err)
			}
			return nil, fmt.Errorf("validating refreshed id token: %w", err)
		}
	}

	return &tokenResponse, nil
}

func (c *Client) ClientAuthenticationParams() (openid.RequestParams, error) {
	switch c.cfg.Client().AuthMethod() {
	case openidconfig.AuthMethodPrivateKeyJWT:
		assertion, err := c.ClientAuthenticationAssertion(DefaultClientAssertionLifetime)
		if err != nil {
			return nil, fmt.Errorf("creating client assertion: %w", err)
		}

		return openid.ClientAuthJwtBearerParams(assertion), nil

	case openidconfig.AuthMethodClientSecret:
		return openid.ClientAuthSecretParams(c.cfg.Client().ClientSecret()), nil
	}

	return nil, fmt.Errorf("unsupported client authentication method: %q", c.cfg.Client().AuthMethod())
}

func (c *Client) ClientAuthenticationAssertion(expiration time.Duration) (string, error) {
	clientCfg := c.cfg.Client()
	providerCfg := c.cfg.Provider()
	key := clientCfg.ClientJWK()

	iat := time.Now()
	exp := iat.Add(expiration)

	tok, err := jwt.NewBuilder().
		Issuer(clientCfg.ClientID()).
		Subject(clientCfg.ClientID()).
		Audience([]string{providerCfg.Issuer()}). // the aud claim is flattened to a single string value on serialization
		IssuedAt(iat).
		Expiration(exp).
		NotBefore(iat).
		JwtID(uuid.New().String()).
		Build()
	if err != nil {
		return "", fmt.Errorf("building client assertion: %w", err)
	}

	alg := clientCfg.ClientJWKAlgorithm()

	opts := make([]jwt.Option, 0)
	if c.cfg.Client().NewClientAuthJWTType() {
		hdrs := jws.NewHeaders()
		if err := hdrs.Set(jws.TypeKey, "client-authentication+jwt"); err != nil {
			return "", fmt.Errorf("setting type header on client assertion: %w", err)
		}
		opts = append(opts, jws.WithProtectedHeaders(hdrs))
	}

	encoded, err := jwt.Sign(tok, jwt.WithKey(alg, key, opts...))
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}

	return string(encoded), nil
}

func (c *Client) oauthPost(ctx context.Context, endpoint string, payload openid.RequestParams) ([]byte, error) {
	clientAuth, err := c.ClientAuthenticationParams()
	if err != nil {
		return nil, err
	}
	payload = payload.With(clientAuth)

	span := trace.SpanFromContext(ctx)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload.URLValues().Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// #nosec G704 -- the endpoint comes from the provider's metadata document, which is
	// fetched from the operator-configured well-known URL at startup; redirects are refused
	// so credentials cannot be forwarded elsewhere
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading server response: %w", err)
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		var errorResponse openid.TokenErrorResponse
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return nil, fmt.Errorf("%w: HTTP %d: unmarshalling error response: %+v", ErrOpenIDClient, resp.StatusCode, err)
		}
		if errorResponse.Error == dpop.ErrorCodeUseNonce {
			span.SetAttributes(attribute.Bool("oauth.dpop_nonce_challenge", true))
			return nil, fmt.Errorf("%w: %w: HTTP %d: %s", ErrOpenIDClient, dpop.ErrUseNonce, resp.StatusCode, errorResponse.ErrorDescription)
		}

		otel.AddErrorEvent(span, "oauthClientError", errorResponse.Error, errors.New(errorResponse.ErrorDescription))
		return nil, fmt.Errorf("%w: HTTP %d: %s: %s", ErrOpenIDClient, resp.StatusCode, errorResponse.Error, errorResponse.ErrorDescription)
	} else if resp.StatusCode >= 500 {
		otel.AddErrorEvent(span, "oauthServerError", ErrOpenIDServer.Error(), errors.New(string(body)))
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrOpenIDServer, resp.StatusCode, body)
	}

	return body, nil
}

// retryNonceChallenge runs request again if the authorization server demands a DPoP nonce.
// request must mint new client authentication parameters per call, as a client assertion cannot be replayed.
func retryNonceChallenge[T any](span trace.Span, request func() (T, error)) (T, error) {
	result, err := request()
	if !dpop.IsNonceChallenge(err) {
		return result, err
	}

	span.SetAttributes(attribute.Bool("oauth.dpop_nonce_challenge", true))
	result, err = request()
	span.SetAttributes(attribute.Bool("oauth.dpop_nonce_retry_succeeded", err == nil))
	return result, err
}

func (c *Client) recordTokenType(span trace.Span, tokenType string) {
	if tokenType == "" {
		return
	}
	span.SetAttributes(attribute.String("oauth.token_type", tokenType))
	if c.dpopProofer != nil && tokenType == openid.TokenTypeBearer {
		log.WithField("logger", "wonderwall.openid").Warn("identity provider returned a bearer token after DPoP was requested")
		span.SetAttributes(attribute.Bool("oauth.token_type_downgraded", true))
	}
}
