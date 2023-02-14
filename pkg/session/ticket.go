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

func (c *Ticket) Crypter() crypto.Crypter {
	if c.crypter == nil {
		c.crypter = crypto.NewCrypter(c.EncryptionKey)
	}
	return c.crypter
}

func (c *Ticket) Key() string {
	return c.SessionKey
}

func (c *Ticket) Set(w http.ResponseWriter, opts cookie.Options, crypter crypto.Crypter) error {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshalling ticket: %w", err)
	}

	return cookie.EncryptAndSet(w, cookie.Session, string(b), opts, crypter)
}

func GetTicket(r *http.Request, crypter crypto.Crypter) (*Ticket, error) {
	ticketJson, err := cookie.GetDecrypted(r, cookie.Session, crypter)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, ErrCookieNotFound
	}
	if errors.Is(err, cookie.ErrInvalidValue) {
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	var ticket Ticket
	err = json.Unmarshal([]byte(ticketJson), &ticket)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling ticket: %w", err)
	}

	return &ticket, nil
}
