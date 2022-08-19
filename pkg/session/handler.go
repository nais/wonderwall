package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sethvargo/go-retry"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	retrypkg "github.com/nais/wonderwall/pkg/retry"
	"github.com/nais/wonderwall/pkg/strings"
)

type Handler struct {
	cfg       *config.Config
	openidCfg openidconfig.Config
	crypter   crypto.Crypter
	store     Store
}

func NewHandler(cfg *config.Config, openidCfg openidconfig.Config, crypter crypto.Crypter) (*Handler, error) {
	store, err := NewStore(cfg)
	if err != nil {
		return nil, err
	}

	return &Handler{
		cfg:       cfg,
		crypter:   crypter,
		openidCfg: openidCfg,
		store:     store,
	}, nil
}

// Create creates and stores a session in the Store, and returns the session's key.
func (h *Handler) Create(r *http.Request, tokens *openid.Tokens, expiresIn time.Duration) (string, error) {
	externalSessionID, err := h.IDOrGenerate(r, tokens)
	if err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}

	key := h.Key(externalSessionID)
	metadata := NewMetadata(time.Now().Add(expiresIn))
	encrypted, err := NewData(externalSessionID, tokens, metadata).Encrypt(h.crypter)
	if err != nil {
		return "", fmt.Errorf("encrypting session data: %w", err)
	}

	retryable := func(ctx context.Context) error {
		err = h.store.Write(r.Context(), key, encrypted, expiresIn)
		if err != nil {
			return retry.RetryableError(err)
		}

		return nil
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return "", fmt.Errorf("writing to store: %w", err)
	}

	return key, nil
}

// DestroyForID destroys a session for a given session ID. Note that a session ID is not equal to a session Key.
func (h *Handler) DestroyForID(r *http.Request, id string) error {
	key := h.Key(id)
	return h.destroyForKey(r, key)
}

func (h *Handler) destroyForKey(r *http.Request, key string) error {
	retryable := func(ctx context.Context) error {
		err := h.store.Delete(r.Context(), key)
		if err == nil {
			return nil
		}

		if errors.Is(err, KeyNotFoundError) {
			return err
		}

		return retry.RetryableError(err)
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return fmt.Errorf("deleting from store: %w", err)
	}

	return nil
}

// Get returns the session data for a given http.Request, matching by the session cookie.
func (h *Handler) Get(r *http.Request) (*Data, error) {
	key, err := cookie.GetDecrypted(r, cookie.Session, h.crypter)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	sessionData, err := h.GetForKey(r, key)
	if err == nil {
		return sessionData, nil
	}

	if errors.Is(err, KeyNotFoundError) {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	return nil, err
}

// GetForID returns the session data for a given session ID.
func (h *Handler) GetForID(r *http.Request, id string) (*Data, error) {
	key := h.Key(id)
	return h.GetForKey(r, key)
}

// GetForKey returns the session data for a given session Key.
func (h *Handler) GetForKey(r *http.Request, key string) (*Data, error) {
	var encryptedSessionData *EncryptedData
	var err error

	retryable := func(ctx context.Context) error {
		encryptedSessionData, err = h.store.Read(ctx, key)
		if err == nil {
			return nil
		}

		if errors.Is(err, KeyNotFoundError) {
			return err
		}

		return retry.RetryableError(err)
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return nil, fmt.Errorf("reading from store: %w", err)
	}

	sessionData, err := encryptedSessionData.Decrypt(h.crypter)
	if err != nil {
		return nil, fmt.Errorf("decrypting session data: %w", err)
	}

	return sessionData, nil
}

// IDOrGenerate returns the session ID, derived from the given request or id_token; e.g. `sid` or `session_state`.
// If none are present, a generated ID is returned.
func (h *Handler) IDOrGenerate(r *http.Request, tokens *openid.Tokens) (string, error) {
	return NewSessionID(h.openidCfg.Provider(), tokens.IDToken, r.URL.Query())
}

// Key prefixes the session ID, e.g. the `sid` or the `session_state` properties from the OpenID provider to prevent key
// collisions in the session Store.
//
// `sid` or `session_state` is a key that refers to the user's unique SSO session at the OpenID Provider.
// The same key is present in all tokens acquired by any Relying Party during that session. Thus, we cannot assume that
// the value of `sid` or `session_state` to uniquely identify the pair of (user, application session) if using a shared
// session store across multiple Relying Parties.
func (h *Handler) Key(sessionID string) string {
	provider := h.openidCfg.Provider()
	client := h.openidCfg.Client()

	return fmt.Sprintf("%s:%s:%s", provider.Name(), client.ClientID(), sessionID)
}

func NewSessionID(cfg openidconfig.Provider, idToken *openid.IDToken, params url.Values) (string, error) {
	// 1. check for 'sid' claim in id_token
	sessionID, err := idToken.GetSidClaim()
	if err == nil {
		return sessionID, nil
	}
	// 1a. error if sid claim is required according to openid config
	if err != nil && cfg.SidClaimRequired() {
		return "", err
	}

	// 2. check for session_state in callback params
	sessionID, err = getSessionStateFrom(params)
	if err == nil {
		return sessionID, nil
	}
	// 2a. error if session_state is required according to openid config
	if err != nil && cfg.SessionStateRequired() {
		return "", err
	}

	// 3. generate ID if all else fails
	sessionID, err = strings.GenerateBase64(64)
	if err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	return sessionID, nil
}

func getSessionStateFrom(params url.Values) (string, error) {
	sessionState := params.Get(openid.SessionState)
	if len(sessionState) == 0 {
		return "", fmt.Errorf("missing required '%s' in params", openid.SessionState)
	}
	return sessionState, nil
}
