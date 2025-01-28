package logging

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/uptrace/opentelemetry-go-extra/otellogrus"
)

func TextFormatter() log.Formatter {
	return &log.TextFormatter{
		DisableTimestamp: false,
		FullTimestamp:    true,
		TimestampFormat:  time.RFC3339Nano,
	}
}

func JsonFormatter() log.Formatter {
	return &log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
}

func Setup(level, format string) error {
	switch format {
	case "json":
		log.SetFormatter(JsonFormatter())
	case "text":
		log.SetFormatter(TextFormatter())
	default:
		return fmt.Errorf("log format '%s' is not recognized", format)
	}

	logLevel, err := log.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("while setting log level: %s", err)
	}

	log.SetLevel(logLevel)
	log.Tracef("Trace logging enabled")

	// Add OpenTelemetry logging hook.
	// This attaches logs to the associated span in the given log context as events.
	log.AddHook(otellogrus.NewHook(otellogrus.WithLevels(
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
	)))

	return nil
}
