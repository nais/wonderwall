package openid

import (
	"fmt"
	"net/url"
	"path"

	"github.com/nais/wonderwall/pkg/router/paths"
)

func RedirectURI(ingress string) (string, error) {
	if len(ingress) == 0 {
		return "", fmt.Errorf("ingress cannot be empty")
	}

	base, err := url.Parse(ingress)
	if err != nil {
		return "", err
	}

	base.Path = path.Join(base.Path, paths.OAuth2, paths.Callback)
	return base.String(), nil
}
