package autologin

import (
	"net/http"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/nais/wonderwall/pkg/config"
)

var DefaultIgnorePatterns = []string{
	"/favicon.ico",
	"/robots.txt",
}

type AutoLogin struct {
	Enabled        bool
	IgnorePatterns []string
	cache          map[string]bool
	lock           sync.Mutex
}

func (a *AutoLogin) NeedsLogin(r *http.Request, isAuthenticated bool) bool {
	if isAuthenticated || !a.Enabled || r.Method != http.MethodGet {
		return false
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	path := r.URL.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}

	if result, found := a.cache[path]; found {
		return result
	}

	for _, pattern := range a.IgnorePatterns {
		match, _ := doublestar.Match(pattern, path)
		if match {
			a.cache[path] = false
			return false
		}
	}

	a.cache[path] = true
	return true
}

func New(cfg *config.Config) (*AutoLogin, error) {
	seen := make(map[string]bool)
	patterns := make([]string, 0)

	for _, path := range append(DefaultIgnorePatterns, cfg.AutoLoginIgnorePaths...) {
		if len(path) == 0 {
			continue
		}

		if path != "/" {
			path = strings.TrimSuffix(path, "/")
		}

		if _, found := seen[path]; !found {
			seen[path] = true
			patterns = append(patterns, path)
		}
	}

	return &AutoLogin{
		Enabled:        cfg.AutoLogin,
		IgnorePatterns: patterns,
		cache:          make(map[string]bool),
	}, nil
}
