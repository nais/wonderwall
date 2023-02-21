package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/nais/liberator/pkg/keygen"

	"github.com/nais/wonderwall/pkg/cookie"
	"github.com/nais/wonderwall/pkg/crypto"
)

// Ticket contains the user agent's data required to access their associated session.
type Ticket struct {
	// SessionKey identifies the session.
	SessionKey string `json:"id"`
	// EncryptionKey is the data encryption key (DEK) used to encrypt the session's data.
	// Its size is equal to the expected key size for the used AEAD, defined in crypto.KeySize.
	EncryptionKey []byte `json:"dek"`
	crypter       crypto.Crypter
}

func NewTicket(sessionKey string) (*Ticket, error) {
	encKey, err := keygen.Keygen(crypto.KeySize)
	if err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}

	return &Ticket{SessionKey: sessionKey, EncryptionKey: encKey}, nil
}

// Crypter returns a crypto.Crypter initialized with the session's data encryption key.
func (c *Ticket) Crypter() crypto.Crypter {
	if c.crypter == nil {
		c.crypter = crypto.NewCrypter(c.EncryptionKey)
	}
	return c.crypter
}

// Key returns the key that identifies the session.
func (c *Ticket) Key() string {
	return c.SessionKey
}

// SetCookie marshals the Ticket, encrypts the value with the given crypto.Crypter, and writes the resulting cookie to the
// given http.ResponseWriter, applying any cookie.Options to the cookie itself.
func (c *Ticket) SetCookie(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter) error {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshalling ticket: %w", err)
	}

	return cookie.EncryptAndSet(w, cookie.Session, string(b), opts, crypter)
}

// getTicket returns a Ticket from the session cookie found in the http.Request, given a crypto.Crypter that
// can decrypt the cookie is provided.
func getTicket(r *http.Request, crypter crypto.Crypter) (*Ticket, error) {
	ticketJson, err := cookie.GetDecrypted(r, cookie.Session, crypter)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, fmt.Errorf("ticket: session cookie: %w", ErrNotFound)
	}
	if errors.Is(err, cookie.ErrInvalidValue) || errors.Is(err, cookie.ErrDecrypt) {
		return nil, fmt.Errorf("ticket: session cookie: %w: %w", ErrInvalid, err)
	}
	if err != nil {
		return nil, err
	}

	var ticket Ticket
	err = json.Unmarshal([]byte(ticketJson), &ticket)
	if err != nil {
		return nil, fmt.Errorf("ticket: unmarshalling: %w", err)
	}

	return &ticket, nil
}
