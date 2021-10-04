package correlationid

import (
	"context"
	"github.com/google/uuid"
	"net/http"
)

// contextKey is the type of contextKeys used for correlation IDs.
type contextKey struct{}

func GetFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKey{}).(string)
	return id, ok
}

func Handler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, contextKey{}, uuid.New().String())
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}
