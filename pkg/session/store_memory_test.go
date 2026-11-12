package session_test

import (
	"testing"

	"github.com/nais/wonderwall/pkg/session"
)

func TestMemory(t *testing.T) {
	testStoreLifecycle(t, session.NewMemory())
}
