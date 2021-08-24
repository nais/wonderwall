package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/nais/wonderwall/pkg/session"
	"net/http"
	"os"

	"github.com/nais/wonderwall/pkg/token"

	"github.com/coreos/go-oidc"
	"github.com/nais/liberator/pkg/conftools"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/router"
)

var maskedConfig = []string{
	config.IDPortenClientJWK,
	config.EncryptionKey,
}

func run() error {
	cfg := config.Initialize()
	if err := conftools.Load(cfg); err != nil {
		return err
	}

	if err := cfg.FetchWellKnownConfig(); err != nil {
		return err
	}

	if err := logging.Setup(cfg.LogLevel, cfg.LogFormat); err != nil {
		return err
	}

	log.Tracef("Trace logging enabled")

	for _, line := range conftools.Format(maskedConfig) {
		log.Info(line)
	}

	scopes := []string{token.ScopeOpenID}

	key, err := base64.StdEncoding.DecodeString(cfg.EncryptionKey)
	if err != nil {
		if len(cfg.EncryptionKey) > 0 {
			return fmt.Errorf("decode encryption key: %w", err)
		}
	}

	if key == nil {
		key, err = cryptutil.RandomBytes(32)
		if err != nil {
			return fmt.Errorf("generate random encryption key: %w", err)
		}
	}

	crypt := cryptutil.New(key)

	var sessionStore session.Store
	if len(cfg.Redis) > 0 {
		redisClient := redis.NewClient(&redis.Options{
			Network: "tcp",
			Addr:    cfg.Redis,
		})
		sessionStore = session.NewRedis(redisClient)
		log.Infof("Using Redis as session backing store")
	} else {
		sessionStore = session.NewMemory()
		log.Warnf("Redis not configured, using in-memory session backing store; not suitable for multi-pod deployments!")
	}

	oauthConfig := oauth2.Config{
		ClientID: cfg.IDPorten.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.IDPorten.WellKnown.AuthorizationEndpoint,
			TokenURL: cfg.IDPorten.WellKnown.TokenEndpoint,
		},
		RedirectURL: cfg.IDPorten.RedirectURI,
		Scopes:      scopes,
	}

	handler := &router.Handler{
		Config:        cfg.IDPorten,
		Crypter:       crypt,
		OauthConfig:   oauthConfig,
		UpstreamHost:  cfg.UpstreamHost,
		SecureCookies: true,
		Sessions:      sessionStore,
		IdTokenVerifier: oidc.NewVerifier(
			cfg.IDPorten.WellKnown.Issuer,
			oidc.NewRemoteKeySet(context.Background(), cfg.IDPorten.WellKnown.JwksURI),
			&oidc.Config{ClientID: cfg.IDPorten.ClientID},
		),
	}

	r := router.New(handler)

	return http.ListenAndServe(cfg.BindAddress, r)
}

func main() {
	err := run()
	if err != nil {
		log.Errorf("Fatal error: %s", err)
		os.Exit(1)
	}
}
