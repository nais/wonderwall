package router

import (
	"errors"
	"fmt"
	"github.com/nais/wonderwall/pkg/config"
	"net/http"
)

var (
	InvalidLoginParameterError = errors.New("InvalidLoginParameter")
)

// LoginURLParameter attempts to get a given parameter from the given HTTP request, falling back if none found.
// The value must exist in the supplied list of supported values.
func LoginURLParameter(r *http.Request, parameter, fallback string, supported config.Supported) (string, error) {
	value := r.URL.Query().Get(parameter)

	if len(value) == 0 {
		value = fallback
	}

	if supported.Contains(value) {
		return value, nil
	}

	return value, fmt.Errorf("%w: invalid value for %s=%s", InvalidLoginParameterError, parameter, value)
}

func PostLogoutRedirectURI(r *http.Request, fallback string) string {
	value := r.URL.Query().Get(PostLogoutRedirectURIParameter)

	if len(value) > 0 {
		return value
	}
	return fallback
}
