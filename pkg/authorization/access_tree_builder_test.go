package authorization

import "testing"

func TestBuildAccessTreesRejectsInvalidPermission(t *testing.T) {
	// Values come off the LPC parser as plain ints; anything outside
	// {-1, 1..5} is malformed and must fail the build rather than resolve to a
	// nonsense permission level.
	for _, bad := range []int{0, 7, -5, 100, -2} {
		raw := map[string]interface{}{
			"access_map": map[string]interface{}{
				"*": map[string]interface{}{".": bad},
			},
		}
		if _, err := BuildAccessTrees(raw); err == nil {
			t.Errorf("BuildAccessTrees accepted out-of-range permission %d, want error", bad)
		}
	}
}

func TestBuildAccessTreesAcceptsValidPermissions(t *testing.T) {
	for _, ok := range []int{-1, 1, 2, 3, 4, 5} {
		raw := map[string]interface{}{
			"access_map": map[string]interface{}{
				"*": map[string]interface{}{".": ok},
			},
		}
		if _, err := BuildAccessTrees(raw); err != nil {
			t.Errorf("BuildAccessTrees rejected valid permission %d: %v", ok, err)
		}
	}
}
