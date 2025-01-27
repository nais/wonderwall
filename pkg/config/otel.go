package config

import (
	flag "github.com/spf13/pflag"
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
	// TODO: automatically enable if OTEL_EXPORTER_OTLP_ENDPOINT env var is set
	flag.Bool(OpenTelemetryEnabled, false, "Enable OpenTelemetry tracing.")
	flag.String(OpenTelemetryServiceName, "wonderwall", "Service name to use for OpenTelemetry.")
}
