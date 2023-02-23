package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/sethvargo/go-retry"

	"github.com/nais/wonderwall/pkg/config"
	"github.com/nais/wonderwall/pkg/crypto"
	retrypkg "github.com/nais/wonderwall/pkg/retry"
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
	ticket, err := getTicket(r, in.cookieCrypter)
	if err != nil {
		return nil, err
	}

	return in.getForTicket(r.Context(), ticket)
}

func (in *reader) getForTicket(ctx context.Context, ticket *Ticket) (*Session, error) {
	var encrypted *EncryptedData
	var err error

	retryable := func(ctx context.Context) error {
		encrypted, err = in.store.Read(ctx, ticket.Key())
		if err == nil {
			return nil
		}

		if errors.Is(err, ErrNotFound) {
			return err
		}

		return retry.RetryableError(err)
	}

	if err := retry.Do(ctx, retrypkg.DefaultBackoff, retryable); err != nil {
		return nil, fmt.Errorf("reading from store: %w", err)
	}

	data, err := encrypted.Decrypt(ticket.Crypter())
	if err != nil {
		return nil, fmt.Errorf("%w: decrypting session data: %w", ErrInvalid, err)
	}

	err = data.Validate()
	if err != nil {
		return nil, err
	}

	return NewSession(data, ticket), nil
}
