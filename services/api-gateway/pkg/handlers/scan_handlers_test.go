package handlers

import "testing"

func TestIsValidPayloadProfile(t *testing.T) {
	valid := []string{"PASSIVE", "LIGHT", "STANDARD", "AGGRESSIVE", "FULL"}
	for _, profile := range valid {
		if !isValidPayloadProfile(profile) {
			t.Errorf("expected profile %s to be valid", profile)
		}
	}
	for _, profile := range []string{"", "unknown", "standard ", "FULL_ACTIVE"} {
		if isValidPayloadProfile(profile) {
			t.Errorf("expected profile %q to be invalid", profile)
		}
	}
}
