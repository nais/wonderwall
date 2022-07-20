package provider

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
)

const (
	JwkMinimumRefreshInterval = 5 * time.Second
)

type Provider interface {
	GetPublicJwkSet(ctx context.Context) (*jwk.Set, error)
	RefreshPublicJwkSet(ctx context.Context) (*jwk.Set, error)
}

type provider struct {
	config    openidconfig.Provider
	jwksCache *jwk.Cache
	jwksLock  *jwksLock
}

type jwksLock struct {
	lastRefresh time.Time
	sync.Mutex
}

func (p *provider) GetPublicJwkSet(ctx context.Context) (*jwk.Set, error) {
	url := p.config.JwksURI()
	set, err := p.jwksCache.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("provider: fetching jwks: %w", err)
	}

	return &set, nil
}

func (p *provider) RefreshPublicJwkSet(ctx context.Context) (*jwk.Set, error) {
	p.jwksLock.Lock()
	defer p.jwksLock.Unlock()

	// redirect to cache if recently refreshed to avoid overwhelming provider
	diff := time.Now().Sub(p.jwksLock.lastRefresh)
	if diff < JwkMinimumRefreshInterval {
		return p.GetPublicJwkSet(ctx)
	}

	p.jwksLock.lastRefresh = time.Now()

	url := p.config.JwksURI()
	set, err := p.jwksCache.Refresh(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("provider: refreshing jwks: %w", err)
	}

	return &set, nil
}

func NewProvider(ctx context.Context, openidCfg openidconfig.Config) (Provider, error) {
	providerCfg := openidCfg.Provider()

	uri := providerCfg.JwksURI()
	cache := jwk.NewCache(ctx)

	err := cache.Register(uri)
	if err != nil {
		return nil, fmt.Errorf("registering jwks provider uri to cache: %w", err)
	}

	// trigger initial fetch and cache of jwk set
	_, err = cache.Refresh(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("initial fetch of jwks from provider: %w", err)
	}

	return &provider{
		config:    providerCfg,
		jwksCache: cache,
		jwksLock:  &jwksLock{},
	}, nil
}
