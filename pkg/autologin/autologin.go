package autologin

import (
	"net/http"
	pathlib "path"
	"strings"

	"github.com/nais/wonderwall/pkg/config"
)

type Options struct {
	Enabled        bool
	IgnorePatterns []string
}

func (o *Options) NeedsLogin(r *http.Request, isAuthenticated bool) bool {
	if isAuthenticated || !o.Enabled {
		return false
	}

	for _, pattern := range o.IgnorePatterns {
		path := r.URL.Path
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		match, _ := pathlib.Match(pattern, r.URL.Path)
		if match {
			return false
		}
	}

	return true
}

func NewOptions(cfg *config.Config) (*Options, error) {
	seen := make(map[string]bool)
	patterns := make([]string, 0)

	for _, path := range cfg.AutoLoginIgnorePaths {
		if len(path) == 0 {
			continue
		}

		if _, found := seen[path]; !found {
			seen[path] = true
			patterns = append(patterns, path)
		}
	}

	return &Options{
		Enabled:        cfg.AutoLogin,
		IgnorePatterns: patterns,
	}, nil
}
