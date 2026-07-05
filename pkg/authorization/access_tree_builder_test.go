package authorization

import "testing"

func TestLoadAccessMapRejectsInvalidPermission(t *testing.T) {
	// Values come off the LPC parser as plain ints; anything outside
	// {-1, 1..5} is malformed and must fail to load rather than resolve to a
	// nonsense permission level.
	for _, bad := range []int{0, 7, -5, 100, -2} {
		raw := map[string]interface{}{
			"access_map": map[string]interface{}{
				"*": map[string]interface{}{".": bad},
			},
		}
		if _, err := loadAccessMap(raw); err == nil {
			t.Errorf("loadAccessMap accepted out-of-range permission %d, want error", bad)
		}
	}
}

func TestLoadAccessMapAcceptsValidPermissions(t *testing.T) {
	for _, ok := range []int{-1, 1, 2, 3, 4, 5} {
		raw := map[string]interface{}{
			"access_map": map[string]interface{}{
				"*": map[string]interface{}{".": ok},
			},
		}
		if _, err := loadAccessMap(raw); err != nil {
			t.Errorf("loadAccessMap rejected valid permission %d: %v", ok, err)
		}
	}
}

func TestLoadAccessMapMissingAccessMap(t *testing.T) {
	if _, err := loadAccessMap(map[string]interface{}{}); err == nil {
		t.Error("loadAccessMap accepted data without an access_map, want error")
	}
}
