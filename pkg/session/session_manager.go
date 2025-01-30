package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/config"
	mw "github.com/nais/wonderwall/pkg/middleware"
	"github.com/nais/wonderwall/pkg/openid"
	openidclient "github.com/nais/wonderwall/pkg/openid/client"
	openidconfig "github.com/nais/wonderwall/pkg/openid/config"
	"github.com/nais/wonderwall/pkg/retry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
	r, span := otel.StartSpanFromRequest(r, "Session.Create")
	defer span.End()
	span.SetAttributes(attribute.Bool("session.created", false))

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

	if err := retry.Do(r.Context(), func(ctx context.Context) error {
		err = in.store.Write(r.Context(), key, encrypted, sessionLifetime)
		return retry.RetryableError(err)
	}); err != nil {
		return nil, fmt.Errorf("writing to store: %w", err)
	}

	sess := NewSession(data, ticket)
	span.SetAttributes(attribute.Bool("session.created", true))
	span.SetAttributes(attribute.String("session.id", sess.ExternalSessionID()))
	return sess, nil
}

func (in *manager) Delete(ctx context.Context, session *Session) error {
	ctx, span := otel.StartSpan(ctx, "Session.Delete")
	defer span.End()
	span.SetAttributes(attribute.String("session.id", session.ExternalSessionID()))
	return in.deleteForKey(ctx, session.key())
}

func (in *manager) DeleteForExternalID(ctx context.Context, id string) error {
	ctx, span := otel.StartSpan(ctx, "Session.DeleteForExternalID")
	defer span.End()
	span.SetAttributes(attribute.String("session.id", id))
	key := in.key(id)
	return in.deleteForKey(ctx, key)
}

func (in *manager) GetOrRefresh(r *http.Request) (*Session, error) {
	r, span := otel.StartSpanFromRequest(r, "Session.GetOrRefresh")
	defer span.End()
	span.SetAttributes(attribute.Bool("session.refreshed", false))

	sess, err := in.Get(r)
	if err != nil {
		return nil, fmt.Errorf("getting session: %w", err)
	}

	if !sess.shouldRefresh() {
		return sess, nil
	}

	refreshed, err := in.Refresh(r, sess)
	if err == nil {
		span.SetAttributes(attribute.Bool("session.refreshed", true))
		return refreshed, nil
	}

	if errors.Is(err, ErrInvalidExternal) || errors.Is(err, ErrInvalid) {
		return nil, err
	}

	if !errors.Is(err, context.Canceled) {
		mw.LogEntryFrom(r).Warnf("session: could not refresh tokens; falling back to existing tokens: %+v", err)
	}

	return sess, nil
}

func (in *manager) Refresh(r *http.Request, sess *Session) (*Session, error) {
	r, span := otel.StartSpanFromRequest(r, "Session.Refresh")
	defer span.End()
	span.SetAttributes(attribute.Bool("session.refreshed", false))
	span.SetAttributes(attribute.String("session.id", sess.ExternalSessionID()))

	if !sess.canRefresh() {
		return sess, nil
	}

	logger := mw.LogEntryFrom(r).WithField("sid", sess.ExternalSessionID())
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
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Warnf("session: releasing lock: %+v", err)
		}
	}(lock, ctx)

	// Get the latest session state again in case it was changed while acquiring the lock
	sess, err = in.getForTicket(ctx, sess.ticket)
	if err != nil {
		return nil, err
	}

	if !sess.canRefresh() {
		logger.Debug("session: already refreshed, aborting refresh attempt.")
		return sess, nil
	}

	logger.Debug("session: performing refresh grant...")
	resp, err := retry.DoValue(ctx, func(ctx context.Context) (*openid.TokenResponse, error) {
		resp, err := in.client.RefreshGrant(ctx, sess.data.RefreshToken)
		if errors.Is(err, openidclient.ErrOpenIDServer) {
			return nil, retry.RetryableError(err)
		}
		if err != nil {
			return nil, err
		}
		return resp, nil
	})
	if err != nil {
		if errors.Is(err, openidclient.ErrOpenIDClient) {
			return nil, fmt.Errorf("%w: authorization might be invalid: %+v", ErrInvalidExternal, err)
		}
		return nil, fmt.Errorf("performing refresh: %w", err)
	}

	sess.data.AccessToken = resp.AccessToken
	sess.data.RefreshToken = resp.RefreshToken
	sess.data.Metadata.Refresh(resp.ExpiresIn)

	if in.cfg.Session.Inactivity {
		sess.data.Metadata.WithTimeout(in.cfg.Session.InactivityTimeout)
	}

	err = in.update(ctx, sess)
	if err != nil {
		return nil, err
	}

	logger.Info("session: successfully refreshed")
	span.SetAttributes(attribute.Bool("session.refreshed", true))
	return sess, nil
}

func (in *manager) deleteForKey(ctx context.Context, key string) error {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.Bool("session.deleted", false))

	if err := retry.Do(ctx, func(ctx context.Context) error {
		err := in.store.Delete(ctx, key)
		if err == nil {
			return nil
		}

		if errors.Is(err, ErrNotFound) {
			return err
		}

		return retry.RetryableError(err)
	}); err != nil {
		return fmt.Errorf("deleting from store: %w", err)
	}

	span.SetAttributes(attribute.Bool("session.deleted", true))
	return nil
}

// key constructs a session key given an external session ID, e.g. the `sid` or the `session_state` properties from the OpenID Connect auth code flow.
func (in *manager) key(externalSessionID string) string {
	clientID := in.openidCfg.Client().ClientID()
	providerName := in.cfg.OpenID.Provider
	return fmt.Sprintf("%s:%s:%s", providerName, clientID, externalSessionID)
}

func (in *manager) update(ctx context.Context, sess *Session) error {
	encrypted, err := sess.encrypt()
	if err != nil {
		return fmt.Errorf("encrypting session data: %w", err)
	}

	if err := retry.Do(ctx, func(ctx context.Context) error {
		err = in.store.Update(ctx, sess.ticket.Key(), encrypted)
		if errors.Is(err, ErrNotFound) {
			return err
		}
		return retry.RetryableError(err)
	}); err != nil {
		return fmt.Errorf("updating in store: %w", err)
	}

	return nil
}
