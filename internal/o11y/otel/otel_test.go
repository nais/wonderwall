package otel_test

import (
	"testing"

	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	// Assert that resource merge doesn't fail due to semconv schema conflicts.
	_, err := otel.Setup(t.Context(), &config.Config{})
	assert.NoError(t, err)
}
