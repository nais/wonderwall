package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nais/liberator/pkg/conftools"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/logging"
	log "github.com/sirupsen/logrus"
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

	fmt.Println("Sleeping for a while")
	time.Sleep(time.Hour * 12)
	return nil
}

func main() {
	err := run()
	if err != nil {
		log.Errorf("Fatal error: %s", err)
		os.Exit(1)
	}
}
