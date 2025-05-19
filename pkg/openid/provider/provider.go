package provider

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/nais/wonderwall/internal/o11y/otel"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"go.opentelemetry.io/otel/attribute"
)

const (
	JwkMinimumRefreshInterval = 5 * time.Second
)

type JwksProvider struct {
	config    openidconfig.Provider
	jwksCache *jwk.Cache
	jwksLock  *jwksLock
}

type jwksLock struct {
	lastRefresh time.Time
	sync.Mutex
}

func (p *JwksProvider) GetPublicJwkSet(ctx context.Context) (*jwk.Set, error) {
	url := p.config.JwksURI()
	set, err := p.jwksCache.Lookup(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("provider: fetching jwks: %w", err)
	}

	set, err = ensureJwkSetWithAlg(set, p.config.IDTokenSigningAlg())
	if err != nil {
		return nil, fmt.Errorf("provider: mutating jwks: %w", err)
	}

	return &set, nil
}

func (p *JwksProvider) RefreshPublicJwkSet(ctx context.Context) (*jwk.Set, error) {
	ctx, span := otel.StartSpan(ctx, "JwksProvider.RefreshPublicJwkSet")
	defer span.End()
	p.jwksLock.Lock()
	defer p.jwksLock.Unlock()

	// redirect to cache if recently refreshed to avoid overwhelming provider
	diff := time.Since(p.jwksLock.lastRefresh)
	if diff < JwkMinimumRefreshInterval {
		span.SetAttributes(attribute.Bool("jwks.cooldown", true))
		return p.GetPublicJwkSet(ctx)
	}

	p.jwksLock.lastRefresh = time.Now()

	url := p.config.JwksURI()
	set, err := p.jwksCache.Refresh(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("provider: refreshing jwks: %w", err)
	}

	set, err = ensureJwkSetWithAlg(set, p.config.IDTokenSigningAlg())
	if err != nil {
		return nil, fmt.Errorf("provider: mutating jwks: %w", err)
	}

	span.SetAttributes(attribute.Bool("jwks.refreshed", true))
	return &set, nil
}

func NewJwksProvider(ctx context.Context, openidCfg openidconfig.Config) (*JwksProvider, error) {
	providerCfg := openidCfg.Provider()

	uri := providerCfg.JwksURI()
	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("creating jwks cache: %w", err)
	}

	if err := cache.Register(ctx, uri); err != nil {
		return nil, fmt.Errorf("registering jwks provider uri to cache: %w", err)
	}

	return &JwksProvider{
		config:    providerCfg,
		jwksCache: cache,
		jwksLock:  &jwksLock{},
	}, nil
}

func ensureJwkSetWithAlg(set jwk.Set, expectedAlg jwa.KeyAlgorithm) (jwk.Set, error) {
	for i := 0; i < set.Len(); i++ {
		key, ok := set.Key(i)
		if !ok {
			continue
		}

		alg, ok := key.Algorithm()
		if ok {
			// drop keys with "alg=none"
			if alg == jwa.NoSignature() {
				if err := set.RemoveKey(key); err != nil {
					return nil, fmt.Errorf("removing key: %w", err)
				}
			}

			// don't mutate keys with a valid algorithm
			continue
		}

		// set "alg" to expected algorithm for keys that don't have one set
		if err := key.Set(jwk.AlgorithmKey, expectedAlg); err != nil {
			return nil, fmt.Errorf("setting key algorithm: %w", err)
		}
	}

	return set, nil
}
