package session

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type memorySessionStore struct {
	lock     sync.Mutex
	sessions map[string]*EncryptedData
}

var _ Store = &memorySessionStore{}

func NewMemory() Store {
	return &memorySessionStore{
		sessions: make(map[string]*EncryptedData),
	}
}

func (s *memorySessionStore) Read(_ context.Context, key string) (*EncryptedData, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	data, ok := s.sessions[key]
	if !ok {
		return nil, fmt.Errorf("%w: no such session: %s", ErrNotFound, key)
	}

	return data, nil
}

func (s *memorySessionStore) Write(_ context.Context, key string, value *EncryptedData, _ time.Duration) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.sessions[key] = value
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

func (s *memorySessionStore) Update(ctx context.Context, key string, value *EncryptedData) error {
	_, err := s.Read(ctx, key)
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.sessions[key] = value
	return nil
}

func (s *memorySessionStore) MakeLock(_ string) Lock {
	return NewNoOpLock()
}
