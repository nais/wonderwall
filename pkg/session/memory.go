package session

import (
	"context"
	"fmt"
	"github.com/nais/wonderwall/pkg/cryptutil"
	"sync"
	"time"
)

type memorySessionStore struct {
	lock     sync.Mutex
	sessions map[string]*EncryptedData
	crypter  cryptutil.Crypter
}

var _ Store = &memorySessionStore{}

func NewMemory(crypter cryptutil.Crypter) Store {
	return &memorySessionStore{
		sessions: make(map[string]*EncryptedData),
		crypter:  crypter,
	}
}

func (s *memorySessionStore) Read(_ context.Context, key string) (*Data, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	data, ok := s.sessions[key]
	if !ok {
		return nil, fmt.Errorf("no such session: %s", key)
	}

	decrypted, err := data.Decrypt(s.crypter)
	if err != nil {
		return nil, fmt.Errorf("decrypting session data: %w", err)
	}

	return decrypted, nil
}

func (s *memorySessionStore) Write(_ context.Context, key string, value *Data, expiration time.Duration) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	encrypted, err := value.Encrypt(s.crypter)
	if err != nil {
		return fmt.Errorf("encrypting session data: %w", err)
	}

	s.sessions[key] = encrypted
	return nil
}

func (s *memorySessionStore) Delete(_ context.Context, keys ...string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, key := range keys {
		delete(s.sessions, key)
	}

	return nil
}
