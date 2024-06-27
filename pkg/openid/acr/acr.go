package acr

import (
	"fmt"
)

const (
	IDPortenLevel3           = "Level3"
	IDPortenLevelSubstantial = "idporten-loa-substantial"
	IDPortenLevel4           = "Level4"
	IDPortenLevelHigh        = "idporten-loa-high"
)

// IDPortenLegacyMapping is a translation table of valid acr_values that maps values from "old" to "new" ID-porten.
var IDPortenLegacyMapping = map[string]string{
	IDPortenLevel3: IDPortenLevelSubstantial,
	IDPortenLevel4: IDPortenLevelHigh,
}

// acceptedValuesMapping is a map of ACR (authentication context class reference) values.
// Each value has an associated list of values that are regarded as equivalent or greater in terms of assurance levels.
// Example:
// - if we require an ACR value of "idporten-loa-substantial", then both "idporten-loa-substantial" and "idporten-loa-high" are accepted values.
// - if we require an ACR value of "idporten-loa-high", then only "idporten-loa-high" is an acceptable value.
var acceptedValuesMapping = map[string][]string{
	IDPortenLevelSubstantial: {IDPortenLevelSubstantial, IDPortenLevelHigh},
	IDPortenLevelHigh:        {IDPortenLevelHigh},
}

func Validate(expected, actual string) error {
	if translated, found := IDPortenLegacyMapping[expected]; found {
		expected = translated
	}

	acceptedValues, found := acceptedValuesMapping[expected]
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
