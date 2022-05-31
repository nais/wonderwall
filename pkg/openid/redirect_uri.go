package openid

import (
	"fmt"
	"net/url"
	"path"

	"github.com/nais/wonderwall/pkg/router/paths"
)

func RedirectURI(ingress, redirectPath string) (string, error) {
	if len(ingress) == 0 {
		return "", fmt.Errorf("ingress cannot be empty")
	}

	base, err := url.Parse(ingress)
	if err != nil {
		return "", err
	}

	base.Path = path.Join(base.Path, paths.OAuth2, redirectPath)
	return base.String(), nil
}
