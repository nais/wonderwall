package main

import (
	"net/http"
	"os"

	"github.com/nais/liberator/pkg/conftools"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/router"
	log "github.com/sirupsen/logrus"
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

	handler := &router.Handler{
		Config: cfg.IDPorten,
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
