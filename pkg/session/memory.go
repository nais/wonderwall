package session

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type memorySessionStore struct {
	lock     sync.Mutex
	sessions map[string]*Data
}

var _ Session = &memorySessionStore{}

func NewMemory() Session {
	return &memorySessionStore{
		sessions: make(map[string]*Data),
	}
}

func (s *memorySessionStore) Read(_ context.Context, key string) (*Data, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	data, ok := s.sessions[key]
	if !ok {
		return nil, fmt.Errorf("no such session: %s", key)
	}
	return data, nil
}

func (s *memorySessionStore) Write(_ context.Context, key string, value *Data, expiration time.Duration) error {
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
