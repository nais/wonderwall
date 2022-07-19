package autologin

import (
	"net/http"
	"regexp"

	"github.com/nais/wonderwall/pkg/config"
)

type Options struct {
	Enabled    bool
	SkipRoutes []Route
}

func (o *Options) NeedsLogin(r *http.Request, isAuthenticated bool) bool {
	if isAuthenticated || !o.Enabled {
		return false
	}

	for _, route := range o.SkipRoutes {
		if route.Regexp.MatchString(r.URL.Path) {
			return false
		}
	}

	return true
}

type Route struct {
	Path   string
	Regexp *regexp.Regexp
}

func NewOptions(cfg *config.Config) (*Options, error) {
	routes, err := skippedRoutes(cfg)
	if err != nil {
		return nil, err
	}

	return &Options{
		Enabled:    cfg.AutoLogin,
		SkipRoutes: routes,
	}, nil
}

func skippedRoutes(cfg *config.Config) ([]Route, error) {
	routes := make([]Route, 0)
	for _, path := range cfg.AutoLoginSkipPaths {
		re, err := regexp.Compile(path)
		if err != nil {
			return nil, err
		}

		routes = append(routes, Route{
			Path:   path,
			Regexp: re,
		})
	}

	return routes, nil
}
