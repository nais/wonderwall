package logging

import (
	"github.com/go-chi/httplog"
	"github.com/rs/zerolog"

	"github.com/nais/wonderwall/pkg/config"
)

func NewHttpLogger(cfg *config.Config) zerolog.Logger {
	opts := httplog.Options{
		Concise: true,
		LogLevel: "warn",
	}

	format := cfg.LogFormat
	switch format {
	case "json":
		opts.JSON = true
	default:
		opts.JSON = false
	}

	return httplog.NewLogger("wonderwall", opts)
}
