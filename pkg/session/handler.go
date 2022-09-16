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
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	retrypkg "github.com/nais/wonderwall/pkg/retry"
	"github.com/nais/wonderwall/pkg/strings"
)

var (
	CookieNotFoundError     = errors.New("cookie not found")
	NoSessionDataError      = errors.New("no session data")
	NoAccessTokenError      = errors.New("no access token in session data")
	ExpiredAccessTokenError = errors.New("access token is expired")
	InvalidStateError       = errors.New("invalid state")
)

const (
	refreshAcquireLockRetryInterval = 10 * time.Millisecond
	refreshAcquireLockTimeout       = 5 * time.Second
	refreshLockDuration             = 2 * time.Second
)

type Handler struct {
	client                 *openidclient.Client
	crypter                crypto.Crypter
	openidCfg              openidconfig.Config
	refreshEnabled         bool
	metadataRolloutEnabled bool
	store                  Store
}

func NewHandler(cfg *config.Config, openidCfg openidconfig.Config, crypter crypto.Crypter, openidClient *openidclient.Client) (*Handler, error) {
	store, err := NewStore(cfg)
	if err != nil {
		return nil, err
	}

	return &Handler{
		crypter:                crypter,
		client:                 openidClient,
		openidCfg:              openidCfg,
		store:                  store,
		refreshEnabled:         cfg.Session.Refresh,
		metadataRolloutEnabled: cfg.Session.MetadataRollout,
	}, nil
}

// Create creates and stores a session in the Store, and returns the session's key.
func (h *Handler) Create(r *http.Request, tokens *openid.Tokens, sessionLifetime time.Duration) (string, error) {
	externalSessionID, err := h.IDOrGenerate(r, tokens)
	if err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}

	key := h.Key(externalSessionID)
	tokenExpiresIn := time.Until(tokens.Expiry)
	metadata := NewMetadata(tokenExpiresIn, sessionLifetime)
	encrypted, err := NewData(externalSessionID, tokens, metadata).Encrypt(h.crypter)
	if err != nil {
		return "", fmt.Errorf("encrypting session data: %w", err)
	}

	retryable := func(ctx context.Context) error {
		err = h.store.Write(r.Context(), key, encrypted, sessionLifetime)
		return retry.RetryableError(err)
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
	key, err := h.GetKey(r)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	return h.GetForKey(r, key)
}

// GetAccessToken returns an access token from the session. If the token is empty or expired, an error is returned.
func (h *Handler) GetAccessToken(r *http.Request) (string, error) {
	sessionData, err := h.GetOrRefresh(r)
	if err != nil {
		return "", err
	}

	if sessionData == nil {
		return "", NoSessionDataError
	}

	if !sessionData.HasAccessToken() {
		return "", NoAccessTokenError
	}

	if h.metadataRolloutEnabled && sessionData.Metadata.IsExpired() {
		return "", ExpiredAccessTokenError
	}

	return sessionData.AccessToken, nil
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

// GetKey extracts the session Key from the session cookie found in the request, if any.
func (h *Handler) GetKey(r *http.Request) (string, error) {
	key, err := cookie.GetDecrypted(r, cookie.Session, h.crypter)
	if err != nil {
		return "", fmt.Errorf("%w: %+v", CookieNotFoundError, err)
	}

	return key, nil
}

// GetOrRefresh returns the session data, performing refreshes if enabled and necessary.
func (h *Handler) GetOrRefresh(r *http.Request) (*Data, error) {
	key, err := h.GetKey(r)
	if err != nil {
		return nil, err
	}

	sessionData, err := h.GetForKey(r, key)
	if err != nil {
		return nil, err
	}

	if !h.shouldRefresh(sessionData) {
		return sessionData, nil
	}

	refreshed, err := h.Refresh(r, key, sessionData)
	if errors.Is(err, InvalidStateError) {
		return nil, err
	} else if err != nil {
		mw.LogEntryFrom(r).Warnf("session: could not refresh tokens; falling back to existing token: %+v", err)
	} else {
		sessionData = refreshed
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

// Refresh refreshes the user's session and returns the updated session data.
func (h *Handler) Refresh(r *http.Request, key string, data *Data) (*Data, error) {
	if !h.canRefresh(data) {
		return data, nil
	}

	logger := mw.LogEntryFrom(r)
	logger.Debug("session: initiating refresh attempt...")

	ctx := r.Context()
	lock := h.store.MakeLock(key)

	logger.Debug("session: acquiring lock...")
	err := func() error {
		timeout := time.NewTimer(refreshAcquireLockTimeout)
		defer timeout.Stop()

		ticker := time.NewTicker(refreshAcquireLockRetryInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("context done: %w", ctx.Err())
			case <-timeout.C:
				return fmt.Errorf("timed out")
			case <-ticker.C:
				err := lock.Acquire(ctx, refreshLockDuration)
				if err == nil {
					return nil
				}

				if !errors.Is(err, AcquireLockError) {
					return fmt.Errorf("unexpected error: %+v", err)
				}
			}
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("while acquiring lock: %w", err)
	}
	defer func(lock Lock, ctx context.Context) {
		err := lock.Release(ctx)
		if err != nil {
			logger.Errorf("session: releasing lock: %+v", err)
		}
	}(lock, ctx)

	// Get the latest session state again in case it was changed while acquiring the lock
	data, err = h.Get(r)
	if err != nil {
		return nil, err
	}

	if !h.canRefresh(data) {
		logger.Debug("session: already refreshed, aborting refresh attempt.")
		return data, nil
	}

	logger.Debug("session: performing refresh grant...")
	var resp *openid.TokenResponse
	refresh := func(ctx context.Context) error {
		resp, err = h.client.RefreshGrant(ctx, data.RefreshToken)
		if errors.Is(err, openidclient.ServerError) {
			return retry.RetryableError(err)
		}

		return err
	}
	if err := retry.Do(ctx, retrypkg.DefaultBackoff, refresh); err != nil {
		if errors.Is(err, openidclient.ClientError) {
			return nil, fmt.Errorf("%w: authorization might be invalid: %+v", InvalidStateError, err)
		}
		return nil, fmt.Errorf("performing refresh: %w", err)
	}

	data.AccessToken = resp.AccessToken
	data.RefreshToken = resp.RefreshToken
	data.Metadata.Refresh(resp.ExpiresIn)

	encrypted, err := data.Encrypt(h.crypter)
	if err != nil {
		return nil, fmt.Errorf("encrypting session data: %w", err)
	}

	update := func(ctx context.Context) error {
		err = h.store.Update(ctx, key, encrypted)
		if errors.Is(err, KeyNotFoundError) {
			return err
		}
		return retry.RetryableError(err)
	}

	if err := retry.Do(ctx, retrypkg.DefaultBackoff, update); err != nil {
		return nil, fmt.Errorf("updating in store: %w", err)
	}

	logger.Info("session: successfully refreshed")
	return data, nil
}

func (h *Handler) canRefresh(data *Data) bool {
	return h.refreshEnabled && data.HasRefreshToken() && !data.Metadata.IsRefreshOnCooldown()
}

func (h *Handler) shouldRefresh(data *Data) bool {
	return h.refreshEnabled && data.HasRefreshToken() && data.Metadata.ShouldRefresh()
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
