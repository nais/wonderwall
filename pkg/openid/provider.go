package openid

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/clients"
	"github.com/nais/wonderwall/pkg/router/paths"
)

const (
	JwkMinimumRefreshInterval = 5 * time.Second
)

type Provider interface {
	GetClientConfiguration() clients.Configuration
	GetOpenIDConfiguration() *Configuration
	GetPublicJwkSet(ctx context.Context) (*jwk.Set, error)
	RefreshPublicJwkSet(ctx context.Context) (*jwk.Set, error)
}

type provider struct {
	clientConfiguration clients.Configuration
	configuration       *Configuration
	jwksCache           *jwk.Cache
	jwksLock            *jwksLock
}

type jwksLock struct {
	lastRefresh time.Time
	sync.Mutex
}

func (p provider) GetClientConfiguration() clients.Configuration {
	return p.clientConfiguration
}

func (p provider) GetOpenIDConfiguration() *Configuration {
	return p.configuration
}

func (p provider) GetPublicJwkSet(ctx context.Context) (*jwk.Set, error) {
	url := p.configuration.JwksURI
	set, err := p.jwksCache.Get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("provider: fetching jwks: %w", err)
	}

	return &set, nil
}

func (p provider) RefreshPublicJwkSet(ctx context.Context) (*jwk.Set, error) {
	p.jwksLock.Lock()
	defer p.jwksLock.Unlock()

	// redirect to cache if recently refreshed to avoid overwhelming provider
	diff := time.Now().Sub(p.jwksLock.lastRefresh)
	if diff < JwkMinimumRefreshInterval {
		return p.GetPublicJwkSet(ctx)
	}

	p.jwksLock.lastRefresh = time.Now()

	url := p.configuration.JwksURI
	set, err := p.jwksCache.Refresh(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("provider: refreshing jwks: %w", err)
	}

	return &set, nil
}

func NewProvider(ctx context.Context, cfg *config.Config) (Provider, error) {
	clientJwkString := cfg.OpenID.ClientJWK
	if len(clientJwkString) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.OpenIDClientJWK)
	}

	clientJwk, err := jwk.ParseKey([]byte(clientJwkString))
	if err != nil {
		return nil, fmt.Errorf("parsing client JWK: %w", err)
	}

	ingress := cfg.Ingress
	if len(ingress) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.Ingress)
	}

	callbackURI, err := RedirectURI(ingress, paths.Callback)
	if err != nil {
		return nil, fmt.Errorf("creating callback URI from ingress: %w", err)
	}

	logoutCallbackURI, err := RedirectURI(ingress, paths.LogoutCallback)
	if err != nil {
		return nil, fmt.Errorf("creating logout callback URI from ingress: %w", err)
	}

	openIDConfig := clients.NewOpenIDConfig(*cfg, clientJwk, callbackURI, logoutCallbackURI)
	var clientConfig clients.Configuration
	switch cfg.OpenID.Provider {
	case config.ProviderIDPorten:
		clientConfig = openIDConfig.IDPorten()
	case config.ProviderAzure:
		clientConfig = openIDConfig.Azure()
	case "":
		return nil, fmt.Errorf("missing required config %s", config.OpenIDProvider)
	default:
		clientConfig = openIDConfig
	}

	if len(clientConfig.GetClientID()) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.OpenIDClientID)
	}

	if len(clientConfig.GetWellKnownURL()) == 0 {
		return nil, fmt.Errorf("missing required config %s", config.OpenIDWellKnownURL)
	}

	configuration, err := FetchWellKnownConfig(clientConfig.GetWellKnownURL())
	if err != nil {
		return nil, fmt.Errorf("fetching well known config: %w", err)
	}

	printConfigs(clientConfig, *configuration)

	acrValues := clientConfig.GetACRValues()
	if len(acrValues) > 0 && !configuration.ACRValuesSupported.Contains(acrValues) {
		return nil, fmt.Errorf("identity provider does not support '%s=%s'", config.OpenIDACRValues, acrValues)
	}

	uiLocales := clientConfig.GetUILocales()
	if len(uiLocales) > 0 && !configuration.UILocalesSupported.Contains(uiLocales) {
		return nil, fmt.Errorf("identity provider does not support '%s=%s'", config.OpenIDUILocales, acrValues)
	}

	uri := configuration.JwksURI
	cache := jwk.NewCache(ctx)

	err = cache.Register(uri)
	if err != nil {
		return nil, fmt.Errorf("registering jwks provider uri to cache: %w", err)
	}

	// trigger initial fetch and cache of jwk set
	_, err = cache.Refresh(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("initial fetch of jwks from provider: %w", err)
	}

	return &provider{
		clientConfiguration: clientConfig,
		configuration:       configuration,
		jwksCache:           cache,
		jwksLock:            &jwksLock{},
	}, nil
}

func printConfigs(clientCfg clients.Configuration, openIdCfg Configuration) {
	log.Info("🤔 openid client configuration 🤔")
	log.Infof("acr values: '%s'", clientCfg.GetACRValues())
	log.Infof("client id: '%s'", clientCfg.GetClientID())
	log.Infof("post-logout redirect uri: '%s'", clientCfg.GetPostLogoutRedirectURI())
	log.Infof("callback uri: '%s'", clientCfg.GetCallbackURI())
	log.Infof("logout callback uri: '%s'", clientCfg.GetLogoutCallbackURI())
	log.Infof("scopes: '%s'", clientCfg.GetScopes())
	log.Infof("ui locales: '%s'", clientCfg.GetUILocales())

	log.Info("😗 openid provider configuration 😗")
	log.Infof("%#v", openIdCfg)
}
