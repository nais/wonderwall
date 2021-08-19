package main

import (
	"net/http"
	"os"
	"time"

	"github.com/caos/oidc/pkg/client/rp"
	"github.com/caos/oidc/pkg/utils"
	"github.com/nais/liberator/pkg/conftools"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/router"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var maskedConfig = []string{
	config.IDPortenClientJWK,
}

var (
	key []byte = []byte("test1234test1234")
)

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

	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	scopes := []string{"openid"}

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
	}

	options = append(options, rp.WithPKCE(cookieHandler))

	relyingParty, err := rp.NewRelyingPartyOIDC(cfg.IDPorten.WellKnown.Issuer, cfg.IDPorten.ClientID, "", cfg.IDPorten.RedirectURI, scopes, options...)
	if err != nil {
		return err
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
		Config:       cfg.IDPorten,
		OauthConfig:  oauthConfig,
		RelyingParty: relyingParty,
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
