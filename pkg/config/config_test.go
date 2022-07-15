package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nais/wonderwall/pkg/config"
)

func TestConfig_Validate(t *testing.T) {
	t.Run("auto-login-skip-paths", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			paths := []string{
				"/some/path",
				"^/some/path$",
				"/some/.+/static/.+$",
			}

			for _, path := range paths {
				t.Run(path, func(t *testing.T) {
					cfg := config.Config{
						AutoLoginSkipPaths: []string{path},
					}

					err := cfg.Validate()
					assert.NoError(t, err)
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			paths := []string{
				"[/some/path",
				"^)/some/path$",
				"[/some/.*$",
				"",
				"\\",
				"/some/path\\",
				"*",
			}

			for _, path := range paths {
				t.Run(path, func(t *testing.T) {
					cfg := config.Config{
						AutoLoginSkipPaths: []string{path},
					}

					err := cfg.Validate()
					assert.Error(t, err)
				})
			}
		})
	})
}
