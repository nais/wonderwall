package mock

import (
	"time"

	"github.com/rs/zerolog"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	"github.com/nais/wonderwall/pkg/router"
	"github.com/nais/wonderwall/pkg/session"
)

func Config() *config.Config {
	return &config.Config{
		EncryptionKey: `G8Roe6AcoBpdr5GhO3cs9iORl4XIC8eq`, // 256 bits AES
		Ingress:       "/",
		OpenID: config.OpenID{
			Provider: "test",
		},
		SessionMaxLifetime: time.Hour,
	}
}

func NewClient(provider openid.Provider) openid.Client {
	return openid.NewClient(*Config(), provider)
}

func NewClientWithCfg(cfg *config.Config, provider openid.Provider) openid.Client {
	return openid.NewClient(*cfg, provider)
}

func NewHandler(provider openid.Provider) *router.Handler {
	cfg := Config()
	return NewHandlerWithCfg(cfg, provider)
}

func NewHandlerWithCfg(cfg *config.Config, provider openid.Provider) *router.Handler {
	if cfg == nil {
		cfg = Config()
	}

	crypter := crypto.NewCrypter([]byte(cfg.EncryptionKey))
	sessionStore := session.NewMemory()

	h, err := router.NewHandler(*cfg, crypter, zerolog.Logger{}, provider, sessionStore)
	if err != nil {
		panic(err)
	}

	h.CookieOptions = h.CookieOptions.WithSecure(false)
	return h
}
