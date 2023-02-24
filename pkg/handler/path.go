package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
)

// GetPath returns the matching context path from the list of registered ingresses.
// If none match, an empty string is returned.
func GetPath(r *http.Request, ingresses *ingress.Ingresses) string {
	path, ok := mw.PathFrom(r.Context())
	if !ok {
		path = ingresses.MatchingPath(r)
	}

	return path
}
