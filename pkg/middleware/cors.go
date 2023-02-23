package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/cors"

	"github.com/nais/wonderwall/pkg/config"
)

func Cors(cfg *config.Config) *cors.Cors {
	ssoDomain := strings.TrimPrefix(cfg.SSO.Domain, ".")

	allowedOrigins := []string{
		fmt.Sprintf("https://*.%s", ssoDomain),
		fmt.Sprintf("https://%s", ssoDomain),
	}

	return cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowCredentials: true,
	})
}
