package openid

import (
	"fmt"

	"github.com/nais/wonderwall/pkg/config"
)

// acrAcceptedValues is a map of ACR (authentication context class reference) values.
// Each value has an associated list of values that are regarded as equivalent or greater in terms of assurance levels.
// Example:
// - if we require an ACR value of "Level3", then both "Level3" and "Level4" are accepted values.
// - if we require an ACR value of "Level4", then only "Level4" is an acceptable value.
var acrAcceptedValues = map[string][]string{
	config.IDPortenAcrLevel3: {config.IDPortenAcrLevel3, config.IDPortenAcrLevel4},
	config.IDPortenAcrLevel4: {config.IDPortenAcrLevel4},
}

func ValidateAcr(expected, actual string) error {
	acceptedValues, found := acrAcceptedValues[expected]
	if !found {
		if expected == actual {
			return nil
		}
		return fmt.Errorf("invalid acr: got %q, expected %q", actual, expected)
	}

	for _, accepted := range acceptedValues {
		if actual == accepted {
			return nil
		}
	}

	return fmt.Errorf("invalid acr: got %q, must be one of %s", actual, acceptedValues)
}
