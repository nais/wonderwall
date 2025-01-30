package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/nais/wonderwall/internal/crypto"
	"github.com/nais/wonderwall/internal/o11y/otel"
	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/retry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var _ Reader = &reader{}

type reader struct {
	cfg           *config.Config
	cookieCrypter crypto.Crypter
	store         Store
}

func NewReader(cfg *config.Config, cookieCrypter crypto.Crypter) (Reader, error) {
	store, err := NewStore(cfg)
	if err != nil {
		return nil, err
	}

	return &reader{
		cfg:           cfg,
		cookieCrypter: cookieCrypter,
		store:         store,
	}, nil
}

func (in *reader) Get(r *http.Request) (*Session, error) {
	r, span := otel.StartSpanFromRequest(r, "Session.Get")
	defer span.End()

	ticket, err := getTicket(r, in.cookieCrypter)
	if err != nil {
		return nil, err
	}

	return in.getForTicket(r.Context(), ticket)
}

func (in *reader) getForTicket(ctx context.Context, ticket *Ticket) (*Session, error) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.Bool("session.valid_session", false))

	encrypted, err := retry.DoValue(ctx, func(ctx context.Context) (*EncryptedData, error) {
		encrypted, err := in.store.Read(ctx, ticket.Key())
		if errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err != nil {
			return nil, retry.RetryableError(err)
		}
		return encrypted, nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading from store: %w", err)
	}

	data, err := encrypted.Decrypt(ticket.Crypter())
	if err != nil {
		return nil, fmt.Errorf("%w: decrypting session data: %w", ErrInvalid, err)
	}

	sess := NewSession(data, ticket)

	err = data.Validate()
	if err != nil {
		return sess, err
	}

	span.SetAttributes(attribute.Bool("session.valid_session", true))
	span.SetAttributes(attribute.String("session.id", sess.ExternalSessionID()))
	return sess, nil
}
