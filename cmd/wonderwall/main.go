package main

import (
	"github.com/nais/liberator/pkg/conftools"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/logging"
	"github.com/nais/wonderwall/pkg/router"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

var maskedConfig = []string{
	config.IDPortenClientJWK,
}

func run() error {
	cfg := config.Initialize()
	err := conftools.Load(cfg)
	if err != nil {
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
