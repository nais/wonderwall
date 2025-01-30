package provider

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nais/wonderwall/internal/o11y/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/lestrrat-go/jwx/v2/jwk"

	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
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
	set, err := p.jwksCache.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("provider: fetching jwks: %w", err)
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
	span.SetAttributes(attribute.Bool("jwks.refreshed", true))
	return &set, nil
}

func NewJwksProvider(ctx context.Context, openidCfg openidconfig.Config) (*JwksProvider, error) {
	providerCfg := openidCfg.Provider()

	uri := providerCfg.JwksURI()
	cache := jwk.NewCache(ctx)

	err := cache.Register(uri, jwk.WithPostFetcher(keySetMutator(providerCfg)))
	if err != nil {
		return nil, fmt.Errorf("registering jwks provider uri to cache: %w", err)
	}

	// trigger initial fetch and cache of jwk set
	_, err = cache.Refresh(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("initial fetch of jwks from provider: %w", err)
	}

	return &JwksProvider{
		config:    providerCfg,
		jwksCache: cache,
		jwksLock:  &jwksLock{},
	}, nil
}

func keySetMutator(cfg openidconfig.Provider) jwk.PostFetcher {
	return jwk.PostFetchFunc(func(uri string, set jwk.Set) (jwk.Set, error) {
		for i := 0; i < set.Len(); i++ {
			key, ok := set.Key(i)
			if !ok || key.Algorithm().String() != "" {
				continue
			}

			// if no "alg" is set on the key, set it to the expected algorithm
			err := key.Set(jwk.AlgorithmKey, cfg.IDTokenSigningAlg())
			if err != nil {
				return nil, fmt.Errorf("setting key algorithm: %w", err)
			}
		}

		return set, nil
	})
}
