package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
	"github.com/nais/wonderwall/pkg/openid"
)

var (
	ErrInvalid         = errors.New("session is invalid")
	ErrInvalidExternal = errors.New("session has invalid state at identity provider")
	ErrNotFound        = errors.New("not found")
)

// Reader knows how to read a session.
type Reader interface {
	// Get returns the session for a given http.Request, or an error if the session is invalid or not found.
	Get(r *http.Request) (*Session, error)
}

// Writer knows how to create, update and delete a session.
type Writer interface {
	// Create creates and stores a session in the Store.
	Create(r *http.Request, tokens *openid.Tokens, sessionLifetime time.Duration) (*Session, error)
	// Delete deletes a session for a given Session.
	Delete(ctx context.Context, session *Session) error
	// DeleteForExternalID deletes a session for a given external session ID (e.g. front-channel logout).
	DeleteForExternalID(ctx context.Context, id string) error
	// Refresh refreshes the user's tokens and returns the updated session. If the session should not be
	// refreshed, it will return the existing session without modifications.
	Refresh(r *http.Request, sess *Session) (*Session, error)
}

// Manager is both a Reader and a Writer.
type Manager interface {
	Reader
	Writer

	// GetOrRefresh returns the session for a given http.Request. If the tokens within the session are expired and the
	// session is still valid, it will automatically attempt to refresh and update the session.
	GetOrRefresh(r *http.Request) (*Session, error)
}

type Session struct {
	data   *Data
	ticket *Ticket
}

func (in *Session) AccessToken() (string, error) {
	if in.data != nil && in.data.HasActiveAccessToken() {
		return in.data.AccessToken, nil
	}

	return "", fmt.Errorf("%w: access token is expired", ErrInvalid)
}

func (in *Session) ExternalSessionID() string {
	return in.data.ExternalSessionID
}

func (in *Session) IDToken() string {
	return in.data.IDToken
}

func (in *Session) MetadataVerbose() MetadataVerbose {
	return in.data.Metadata.Verbose()
}

func (in *Session) MetadataVerboseRefresh() MetadataVerboseWithRefresh {
	return in.data.Metadata.VerboseWithRefresh()
}

func (in *Session) SetCookie(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter) error {
	return in.ticket.SetCookie(w, opts, crypter)
}

func (in *Session) canRefresh() bool {
	return in.data != nil && in.data.HasRefreshToken() && !in.data.Metadata.IsRefreshOnCooldown()
}

func (in *Session) encrypt() (*EncryptedData, error) {
	return in.data.Encrypt(in.ticket.Crypter())
}

func (in *Session) key() string {
	return in.ticket.Key()
}

func (in *Session) shouldRefresh() bool {
	return in.data != nil && in.data.Metadata.ShouldRefresh()
}

func NewSession(data *Data, ticket *Ticket) *Session {
	return &Session{data: data, ticket: ticket}
}
