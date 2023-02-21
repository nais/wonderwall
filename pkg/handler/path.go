package handler

import (
	"net/http"

	"github.com/nais/wonderwall/pkg/ingress"
	mw "github.com/nais/wonderwall/pkg/middleware"
)

type PathSource interface {
	GetIngresses() *ingress.Ingresses
}

// GetPath returns the matching context path from the list of registered ingresses.
// If none match, an empty string is returned.
func GetPath(r *http.Request, src PathSource) string {
	path, ok := mw.PathFrom(r.Context())
	if !ok {
		path = src.GetIngresses().MatchingPath(r)
	}

	return path
}
