package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sethvargo/go-retry"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	retrypkg "github.com/nais/wonderwall/pkg/retry"
)

const (
	refreshAcquireLockRetryInterval = 10 * time.Millisecond
	refreshAcquireLockTimeout       = 15 * time.Second
	refreshLockDuration             = 10 * time.Second
)

var _ Manager = &manager{}

type manager struct {
	*reader
	cfg       *config.Config
	client    *openidclient.Client
	openidCfg openidconfig.Config
	store     Store
}

func NewManager(cfg *config.Config, openidCfg openidconfig.Config, crypter crypto.Crypter, openidClient *openidclient.Client) (Manager, error) {
	store, err := NewStore(cfg)
	if err != nil {
		return nil, err
	}

	rd := &reader{
		cfg:           cfg,
		cookieCrypter: crypter,
		store:         store,
	}

	return &manager{
		reader:    rd,
		cfg:       cfg,
		client:    openidClient,
		openidCfg: openidCfg,
		store:     store,
	}, nil
}

func (in *manager) Create(r *http.Request, tokens *openid.Tokens, sessionLifetime time.Duration) (*Session, error) {
	externalSessionID, err := ExternalID(r, in.openidCfg.Provider(), tokens.IDToken)
	if err != nil {
		return nil, fmt.Errorf("generating session ID: %w", err)
	}

	key := in.key(externalSessionID)
	tokenExpiresIn := time.Until(tokens.Expiry)
	metadata := NewMetadata(tokenExpiresIn, sessionLifetime)

	if in.cfg.Session.Inactivity {
		metadata.WithTimeout(in.cfg.Session.InactivityTimeout)
	}

	ticket, err := NewTicket(key)
	if err != nil {
		return nil, fmt.Errorf("making ticket: %w", err)
	}

	data := NewData(externalSessionID, tokens, metadata)

	encrypted, err := data.Encrypt(ticket.Crypter())
	if err != nil {
		return nil, fmt.Errorf("encrypting session data: %w", err)
	}

	retryable := func(ctx context.Context) error {
		err = in.store.Write(r.Context(), key, encrypted, sessionLifetime)
		return retry.RetryableError(err)
	}

	if err := retry.Do(r.Context(), retrypkg.DefaultBackoff, retryable); err != nil {
		return nil, fmt.Errorf("writing to store: %w", err)
	}

	return NewSession(data, ticket), nil
}

func (in *manager) Delete(ctx context.Context, session *Session) error {
	return in.deleteForKey(ctx, session.Key())
}

func (in *manager) DeleteForExternalID(ctx context.Context, id string) error {
	key := in.key(id)
	return in.deleteForKey(ctx, key)
}

func (in *manager) GetOrRefresh(r *http.Request) (*Session, error) {
	sess, err := in.Get(r)
	if err != nil {
		return nil, fmt.Errorf("getting session: %w", err)
	}

	if !sess.ShouldRefresh() {
		return sess, nil
	}

	refreshed, err := in.Refresh(r, sess)
	if errors.Is(err, ErrInvalidExternal) || errors.Is(err, ErrInvalid) {
		return nil, err
	} else if err != nil {
		mw.LogEntryFrom(r).Warnf("session: could not refresh tokens; falling back to existing tokens: %+v", err)
	} else {
		sess = refreshed
	}

	return sess, nil
}

func (in *manager) Refresh(r *http.Request, sess *Session) (*Session, error) {
	if !in.cfg.Session.Refresh || !sess.CanRefresh() {
		return sess, nil
	}

	logger := mw.LogEntryFrom(r)
	logger.Debug("session: initiating refresh attempt...")

	ctx := r.Context()
	lock := in.store.MakeLock(sess.ticket.Key())

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

				if !errors.Is(err, ErrAcquireLock) {
					return err
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
			logger.Warnf("session: releasing lock: %+v", err)
		}
	}(lock, ctx)

	// Get the latest session state again in case it was changed while acquiring the lock
	sess, err = in.GetForTicket(ctx, sess.ticket)
	if err != nil {
		return nil, err
	}

	if !sess.CanRefresh() {
		logger.Debug("session: already refreshed, aborting refresh attempt.")
		return sess, nil
	}

	logger.Debug("session: performing refresh grant...")
	var resp *openid.TokenResponse
	refresh := func(ctx context.Context) error {
		resp, err = in.client.RefreshGrant(ctx, sess.data.RefreshToken)
		if errors.Is(err, openidclient.ErrOpenIDServer) {
			return retry.RetryableError(err)
		}

		return err
	}
	if err := retry.Do(ctx, retrypkg.DefaultBackoff, refresh); err != nil {
		if errors.Is(err, openidclient.ErrOpenIDClient) {
			return nil, fmt.Errorf("%w: authorization might be invalid: %+v", ErrInvalidExternal, err)
		}
		return nil, fmt.Errorf("performing refresh: %w", err)
	}

	sess.data.AccessToken = resp.AccessToken
	sess.data.RefreshToken = resp.RefreshToken
	sess.data.Metadata.Refresh(resp.ExpiresIn)

	if in.cfg.Session.Inactivity {
		sess.data.Metadata.ExtendTimeout(in.cfg.Session.InactivityTimeout)
	}

	err = in.update(ctx, sess)
	if err != nil {
		return nil, err
	}

	logger.Info("session: successfully refreshed")
	return sess, nil
}

func (in *manager) deleteForKey(ctx context.Context, key string) error {
	retryable := func(ctx context.Context) error {
		err := in.store.Delete(ctx, key)
		if err == nil {
			return nil
		}

		if errors.Is(err, ErrNotFound) {
			return err
		}

		return retry.RetryableError(err)
	}

	if err := retry.Do(ctx, retrypkg.DefaultBackoff, retryable); err != nil {
		return fmt.Errorf("deleting from store: %w", err)
	}

	return nil
}

// key constructs a session key given an external session ID, e.g. the `sid` or the `session_state` properties from the OpenID Connect auth code flow.
func (in *manager) key(externalSessionID string) string {
	clientID := in.openidCfg.Client().ClientID()
	providerName := in.cfg.OpenID.Provider
	return fmt.Sprintf("%s:%s:%s", providerName, clientID, externalSessionID)
}

func (in *manager) update(ctx context.Context, sess *Session) error {
	encrypted, err := sess.Encrypt()
	if err != nil {
		return fmt.Errorf("encrypting session data: %w", err)
	}

	update := func(ctx context.Context) error {
		err = in.store.Update(ctx, sess.ticket.Key(), encrypted)
		if errors.Is(err, ErrNotFound) {
			return err
		}
		return retry.RetryableError(err)
	}

	if err := retry.Do(ctx, retrypkg.DefaultBackoff, update); err != nil {
		return fmt.Errorf("updating in store: %w", err)
	}

	return nil
}
