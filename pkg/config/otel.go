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
	flag.Bool(OpenTelemetryEnabled, false, "Enable OpenTelemetry tracing.")
	flag.String(OpenTelemetryServiceName, "wonderwall", "Service name to use for OpenTelemetry.")
}
