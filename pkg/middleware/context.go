package middleware

import (
	"context"
	"net/http"

	"github.com/nais/wonderwall/pkg/ingress"
)

type contextKey string

const (
	ctxAccessToken = contextKey("AccessToken")
	ctxAcr         = contextKey("Acr")
	ctxAmr         = contextKey("Amr")
	ctxAuthTime    = contextKey("AuthTime")
	ctxSessionID   = contextKey("SessionID")
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

func AcrFrom(ctx context.Context) (string, bool) {
	acr, ok := ctx.Value(ctxAcr).(string)
	return acr, ok
}

func WithAcr(ctx context.Context, acr string) context.Context {
	return context.WithValue(ctx, ctxAcr, acr)
}

func AmrFrom(ctx context.Context) (string, bool) {
	amr, ok := ctx.Value(ctxAmr).(string)
	return amr, ok
}

func WithAmr(ctx context.Context, amr string) context.Context {
	return context.WithValue(ctx, ctxAmr, amr)
}

func AuthTimeFrom(ctx context.Context) (string, bool) {
	authTime, ok := ctx.Value(ctxAuthTime).(string)
	return authTime, ok
}

func WithAuthTime(ctx context.Context, authTime string) context.Context {
	return context.WithValue(ctx, ctxAuthTime, authTime)
}

func SessionIDFrom(ctx context.Context) (string, bool) {
	sessionID, ok := ctx.Value(ctxSessionID).(string)
	return sessionID, ok
}

func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, ctxSessionID, sessionID)
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
