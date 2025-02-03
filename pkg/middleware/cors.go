package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/cors"

	"github.com/nais/wonderwall/pkg/config"
)

func Cors(cfg *config.Config, methods []string) func(http.Handler) http.Handler {
	ssoDomain := strings.TrimPrefix(cfg.SSO.Domain, ".")

	allowedOrigins := []string{
		fmt.Sprintf("https://*.%s", ssoDomain),
		fmt.Sprintf("https://%s", ssoDomain),
	}

	return cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   methods,
		AllowCredentials: true,
		// This reflects the request headers, essentially allowing all headers.
		AllowedHeaders: []string{"*"},
	}).Handler
}
