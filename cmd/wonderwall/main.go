package main

import (
	"github.com/nais/liberator/pkg/conftools"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/router"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"net/http"
	"os"
)

var maskedConfig = []string{
	config.IDPortenClientJWK,
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

	for _, line := range conftools.Format(maskedConfig) {
		log.Info(line)
	}

	scopes := []string{router.ScopeOpenID}

	key, err := cryptutil.RandomBytes(32)
	if err != nil {
		return err
	}
	crypt := cryptutil.New(key)

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
		Config:      cfg.IDPorten,
		OauthConfig: oauthConfig,
		Crypter:     crypt,
	}

	handler.Init()

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
