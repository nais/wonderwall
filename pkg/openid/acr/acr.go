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

// IDPortenMapping is a translation table of valid acr_values for migrating between old and new ID-porten.
var IDPortenMapping = map[string]string{
	IDPortenLevel3:           IDPortenLevelSubstantial,
	IDPortenLevelSubstantial: IDPortenLevel3,
	IDPortenLevel4:           IDPortenLevelHigh,
	IDPortenLevelHigh:        IDPortenLevel4,
}

// acceptedValuesMapping is a map of ACR (authentication context class reference) values.
// Each value has an associated list of values that are regarded as equivalent or greater in terms of assurance levels.
// Example:
// - if we require an ACR value of "Level3", then both "Level3" and "Level4" are accepted values.
// - if we require an ACR value of "Level4", then only "Level4" is an acceptable value.
var acceptedValuesMapping = map[string][]string{
	IDPortenLevel3:           {IDPortenLevel3, IDPortenLevel4, IDPortenLevelSubstantial, IDPortenLevelHigh},
	IDPortenLevelSubstantial: {IDPortenLevel3, IDPortenLevel4, IDPortenLevelSubstantial, IDPortenLevelHigh},
	IDPortenLevel4:           {IDPortenLevel4, IDPortenLevelHigh},
	IDPortenLevelHigh:        {IDPortenLevel4, IDPortenLevelHigh},
}

func Validate(expected, actual string) error {
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
