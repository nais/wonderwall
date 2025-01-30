package config

import (
	"os"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type OpenTelemetry struct {
	Enabled     bool   `json:"enabled"`
	ServiceName string `json:"service-name"`
}

const (
	OpenTelemetryEnabled     = "otel.enabled"
	OpenTelemetryServiceName = "otel.service-name"
)

func otelFlags() {
	flag.Bool(OpenTelemetryEnabled, false, "Enable OpenTelemetry tracing.")
	flag.String(OpenTelemetryServiceName, "wonderwall", "Service name to use for OpenTelemetry.")
}

func resolveOtel() {
	otelEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otelEndpoint != "" {
		logger.Infof("config: OTLP endpoint set to %q, enabling OpenTelemetry", otelEndpoint)
		viper.Set(OpenTelemetryEnabled, "true")
	}

	otelServiceName := os.Getenv("OTEL_SERVICE_NAME")
	if otelServiceName != "" {
		logger.Infof("config: OTEL_SERVICE_NAME set to %q; overriding %q flag", otelServiceName, OpenTelemetryServiceName)
		viper.Set(OpenTelemetryServiceName, otelServiceName)
	}
}
