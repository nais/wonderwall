package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/jwt"
	"github.com/nais/wonderwall/pkg/openid/provider"
)

const (
	ExternalIDCookieName  = "wonderwall-1"
	IDTokenCookieName     = "wonderwall-2"
	AccessTokenCookieName = "wonderwall-3"
)

type CookieStore interface {
	Write(data *Data, expiration time.Duration) error
	Read(ctx context.Context) (*Data, error)
	Delete()
}

type cookieSessionStore struct {
	req        *http.Request
	rw         http.ResponseWriter
	crypter    crypto.Crypter
	provider   provider.Provider
	cookieOpts cookie.Options
}

var _ CookieStore = &cookieSessionStore{}

func NewCookie(rw http.ResponseWriter, req *http.Request, crypter crypto.Crypter, provider provider.Provider, opts cookie.Options) CookieStore {
	return &cookieSessionStore{
		req:        req,
		rw:         rw,
		crypter:    crypter,
		provider:   provider,
		cookieOpts: opts,
	}
}

func (c cookieSessionStore) Write(data *Data, expiration time.Duration) error {
	opts := c.cookieOpts.WithExpiresIn(expiration)

	err := c.setCookie(ExternalIDCookieName, data.ExternalSessionID, opts)
	if err != nil {
		return fmt.Errorf("setting session id fallback cookie: %w", err)
	}

	err = c.setCookie(IDTokenCookieName, data.IDToken, opts)
	if err != nil {
		return fmt.Errorf("setting session id_token fallback cookie: %w", err)
	}

	err = c.setCookie(AccessTokenCookieName, data.AccessToken, opts)
	if err != nil {
		return fmt.Errorf("setting session access_token fallback cookie: %w", err)
	}

	return nil
}

func (c cookieSessionStore) Read(ctx context.Context) (*Data, error) {
	externalSessionID, err := c.getValue(ExternalIDCookieName)
	if err != nil {
		return nil, fmt.Errorf("reading session ID from fallback cookie: %w", err)
	}

	idToken, err := c.getValue(IDTokenCookieName)
	if err != nil {
		return nil, fmt.Errorf("reading id_token from fallback cookie: %w", err)
	}

	accessToken, err := c.getValue(AccessTokenCookieName)
	if err != nil {
		return nil, fmt.Errorf("reading access_token from fallback cookie: %w", err)
	}

	jwkSet, err := c.provider.GetPublicJwkSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("callback: getting jwks: %w", err)
	}

	tokens, err := jwt.ParseTokensFromStrings(idToken, accessToken, *jwkSet)
	if err != nil {
		// JWKS might not be up-to-date, so we'll want to force a refresh for the next attempt
		_, _ = c.provider.RefreshPublicJwkSet(ctx)
		return nil, fmt.Errorf("parsing tokens: %w", err)
	}

	// TODO: set refresh token and metadata
	return NewData(externalSessionID, tokens, "", nil), nil
}

func (c cookieSessionStore) Delete() {
	for _, name := range c.allCookieNames() {
		c.deleteIfNotFound(name)
	}
}

func (c cookieSessionStore) allCookieNames() []string {
	return []string{
		ExternalIDCookieName,
		IDTokenCookieName,
		AccessTokenCookieName,
	}
}

func (c cookieSessionStore) deleteIfNotFound(cookieName string) {
	_, err := c.req.Cookie(cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return
	}

	cookie.Clear(c.rw, cookieName, c.cookieOpts)
}

func (c cookieSessionStore) setCookie(name, value string, opts cookie.Options) error {
	return cookie.EncryptAndSet(c.rw, name, value, opts, c.crypter)
}

func (c cookieSessionStore) getValue(name string) (string, error) {
	return cookie.GetDecrypted(c.req, name, c.crypter)
}
