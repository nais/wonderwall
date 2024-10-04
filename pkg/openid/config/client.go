package config

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/openid/scopes"
)

type AuthMethod string

const (
	AuthMethodPrivateKeyJWT AuthMethod = "private_key_jwt"
	AuthMethodClientSecret  AuthMethod = "client_secret"
)

type Client interface {
	ACRValues() string
	Audiences() map[string]bool
	AuthMethod() AuthMethod
	ClientID() string
	ClientJWK() jwk.Key
	ClientSecret() string
	PostLogoutRedirectURI() string
	ResourceIndicator() string
	Scopes() scopes.Scopes
	UILocales() string
	WellKnownURL() string
}

type client struct {
	config.OpenID
	authMethod       AuthMethod
	clientJwk        jwk.Key
	trustedAudiences map[string]bool
}

func (in *client) ACRValues() string {
	return in.OpenID.ACRValues
}

func (in *client) Audiences() map[string]bool {
	return in.trustedAudiences
}

func (in *client) AuthMethod() AuthMethod {
	return in.authMethod
}

func (in *client) ClientID() string {
	return in.OpenID.ClientID
}

func (in *client) ClientJWK() jwk.Key {
	return in.clientJwk
}

func (in *client) ClientSecret() string {
	return in.OpenID.ClientSecret
}

func (in *client) PostLogoutRedirectURI() string {
	return in.OpenID.PostLogoutRedirectURI
}

func (in *client) ResourceIndicator() string {
	return in.OpenID.ResourceIndicator
}

func (in *client) Scopes() scopes.Scopes {
	return scopes.DefaultScopes().WithAdditional(in.OpenID.Scopes...)
}

func (in *client) UILocales() string {
	return in.OpenID.UILocales
}

func (in *client) WellKnownURL() string {
	return in.OpenID.WellKnownURL
}

func NewClientConfig(cfg *config.Config) (Client, error) {
	c := &client{
		OpenID:           cfg.OpenID,
		trustedAudiences: cfg.OpenID.TrustedAudiences(),
	}

	if len(cfg.OpenID.ClientJWK) == 0 && len(cfg.OpenID.ClientSecret) == 0 {
		return nil, fmt.Errorf("missing required config: at least one of %q or %q must be set", config.OpenIDClientJWK, config.OpenIDClientSecret)
	}

	if len(cfg.OpenID.ClientSecret) > 0 {
		c.authMethod = AuthMethodClientSecret
	}

	if len(cfg.OpenID.ClientJWK) > 0 {
		if c.authMethod == AuthMethodClientSecret {
			log.WithField("logger", "wonderwall.config").Info("both client JWK and client secret were set; using client JWK...")
		}

		clientJwk, err := jwk.ParseKey([]byte(cfg.OpenID.ClientJWK))
		if err != nil {
			return nil, fmt.Errorf("parsing client JWK: %w", err)
		}

		c.clientJwk = clientJwk
		c.authMethod = AuthMethodPrivateKeyJWT
	}

	var clientConfig Client
	switch cfg.OpenID.Provider {
	case config.ProviderIDPorten:
		clientConfig = c.IDPorten()
	case config.ProviderAzure:
		clientConfig = c.Azure()
	case "":
		return nil, fmt.Errorf("missing required config %q", config.OpenIDProvider)
	default:
		clientConfig = c
	}

	if len(clientConfig.ClientID()) == 0 {
		return nil, fmt.Errorf("missing required config %q", config.OpenIDClientID)
	}

	if len(clientConfig.WellKnownURL()) == 0 {
		return nil, fmt.Errorf("missing required config %q", config.OpenIDWellKnownURL)
	}

	return clientConfig, nil
}

type azure struct {
	*client
}

func (in *client) Azure() *azure {
	return &azure{
		client: in,
	}
}

func (in *azure) Scopes() scopes.Scopes {
	return scopes.DefaultScopes().
		WithAzureScope(in.OpenID.ClientID).
		WithOfflineAccess().
		WithAdditional(in.OpenID.Scopes...)
}

type idporten struct {
	*client
}

func (in *client) IDPorten() *idporten {
	return &idporten{
		client: in,
	}
}
