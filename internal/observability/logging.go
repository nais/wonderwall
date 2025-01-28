package observability

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

func textFormatter() log.Formatter {
	return &log.TextFormatter{
		DisableTimestamp: false,
		FullTimestamp:    true,
		TimestampFormat:  time.RFC3339Nano,
	}
}

func jsonFormatter() log.Formatter {
	return &log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
}

func SetupLogger(level, format string) error {
	switch format {
	case "json":
		log.SetFormatter(jsonFormatter())
	case "text":
		log.SetFormatter(textFormatter())
	default:
		return fmt.Errorf("log format '%s' is not recognized", format)
	}

	logLevel, err := log.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("while setting log level: %s", err)
	}

	log.SetLevel(logLevel)
	log.Tracef("Trace logging enabled")

	return nil
}
