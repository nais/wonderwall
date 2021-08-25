package config

import (
	"net/url"
	"strings"
)

func ParseIngresses(ingresses []string) []string {
	prefixMap := make(map[string]interface{})

	for _, ingress := range ingresses {
		ingressURL, err := url.Parse(ingress)
		if err != nil {
			continue
		}
		path := ingressURL.Path
		path = strings.TrimRight(path, "/")

		prefixMap[path] = new(interface{})
	}

	prefixes := make([]string, 0)
	for prefix := range prefixMap {
		prefixes = append(prefixes, prefix)
	}

	return prefixes
}
