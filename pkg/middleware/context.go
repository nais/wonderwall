package middleware

import (
	"context"
	"net/http"

	"github.com/nais/wonderwall/pkg/ingress"
)

type contextKey string

const (
	ctxAccessToken = contextKey("AccessToken")
	ctxIdToken     = contextKey("IdToken")
	ctxIngress     = contextKey("Ingress")
	ctxPath        = contextKey("Path")
)

func AccessTokenFrom(ctx context.Context) (string, bool) {
	accessToken, ok := ctx.Value(ctxAccessToken).(string)
	return accessToken, ok
}

func WithAccessToken(ctx context.Context, accessToken string) context.Context {
	return context.WithValue(ctx, ctxAccessToken, accessToken)
}

func IdTokenFrom(ctx context.Context) (string, bool) {
	idToken, ok := ctx.Value(ctxIdToken).(string)
	return idToken, ok
}

func WithIdToken(ctx context.Context, idToken string) context.Context {
	return context.WithValue(ctx, ctxIdToken, idToken)
}

func IngressFrom(ctx context.Context) (ingress.Ingress, bool) {
	i, ok := ctx.Value(ctxIngress).(ingress.Ingress)
	return i, ok
}

func WithIngress(ctx context.Context, ingress ingress.Ingress) context.Context {
	return context.WithValue(ctx, ctxIngress, ingress)
}

func RequestWithIngress(r *http.Request, ing ingress.Ingress) *http.Request {
	ctx := r.Context()
	ctx = WithIngress(ctx, ing)
	return r.WithContext(ctx)
}

func PathFrom(ctx context.Context) (string, bool) {
	path, ok := ctx.Value(ctxPath).(string)
	return path, ok
}

func WithPath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, ctxPath, path)
}

func RequestWithPath(r *http.Request, path string) *http.Request {
	ctx := r.Context()
	ctx = WithPath(ctx, path)
	return r.WithContext(ctx)
}
