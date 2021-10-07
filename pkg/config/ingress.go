package config

import (
	"net/url"
	"strings"
)

func ParseIngress(ingress string) string {
	ingressURL, err := url.Parse(ingress)
	if err != nil {
		return ""
	}
	path := ingressURL.Path
	path = strings.TrimRight(path, "/")

	return path
}
