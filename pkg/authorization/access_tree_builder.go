package authorization

import "fmt"

// loadAccessMap extracts the "access_map" from raw parsed data and validates
// it. Resolution works directly on the raw map (mirroring the MUD), so this
// only checks structure and permission ranges up front so a malformed file
// fails to load rather than resolving to nonsense at request time.
func loadAccessMap(rawData map[string]interface{}) (map[string]interface{}, error) {
	accessMap, ok := rawData["access_map"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("access_map not found or invalid format")
	}
	if err := validateNode(accessMap); err != nil {
		return nil, err
	}
	return accessMap, nil
}

// validateNode recursively checks that every leaf is a valid permission, every
// subtree is a map, and every "?" entry is a list of group-name strings.
func validateNode(node map[string]interface{}) error {
	for key, value := range node {
		switch v := value.(type) {
		case map[string]interface{}:
			if err := validateNode(v); err != nil {
				return err
			}
		case []interface{}:
			if key != "?" {
				return fmt.Errorf("unexpected list value for key %q", key)
			}
			for _, g := range v {
				if _, ok := g.(string); !ok {
					return fmt.Errorf("invalid group name format: expected string, got %T", g)
				}
			}
		default:
			if _, err := parsePermission(value); err != nil {
				return fmt.Errorf("key %q: %w", key, err)
			}
		}
	}
	return nil
}

// parsePermission converts a raw permission value into a Permission and rejects
// values outside the defined range, so a malformed access tree fails to build
// rather than silently granting (e.g. a stray 7 reading as CanGrant) or
// blocking resolution with a nonsense level.
func parsePermission(value interface{}) (Permission, error) {
	var perm Permission
	switch v := value.(type) {
	case float64:
		perm = Permission(int(v))
	case int:
		perm = Permission(v)
	case Permission:
		perm = v
	default:
		return Revoked, fmt.Errorf("invalid permission format: expected number or Permission, got %T", value)
	}

	if !perm.isValid() {
		return Revoked, fmt.Errorf("permission value out of range: %d", int(perm))
	}
	return perm, nil
}
