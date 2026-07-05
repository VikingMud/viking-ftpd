package authorization

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/mmcdole/viking-ftpd/pkg/logging"
	"github.com/mmcdole/viking-ftpd/pkg/users"
)

// Authorizer resolves per-path permissions against the MUD's access map,
// mirroring the MUD's own resolver (resources/access.c: _get_access / eval_map).
// The access map is cached and refreshed on a TTL.
type Authorizer struct {
	source        AccessSource
	characterData users.Source
	cacheDuration time.Duration

	mu          sync.RWMutex
	accessMap   map[string]interface{} // raw "access_map": name -> raw tree
	lastRefresh time.Time
}

// NewAuthorizer creates a new Authorizer instance
func NewAuthorizer(source AccessSource, characterData users.Source, cacheDuration time.Duration) *Authorizer {
	return &Authorizer{
		source:        source,
		characterData: characterData,
		cacheDuration: cacheDuration,
	}
}

// HasPermission checks if a user has the required permission for a path
func (a *Authorizer) HasPermission(username string, filepath string, requiredPerm Permission) bool {
	return a.ResolvePermission(username, filepath) >= requiredPerm
}

// CanRead checks if a user has read permission for a path
func (a *Authorizer) CanRead(username string, filepath string) bool {
	return a.ResolvePermission(username, filepath).CanRead()
}

// CanWrite checks if a user has write permission for a path
func (a *Authorizer) CanWrite(username string, filepath string) bool {
	return a.ResolvePermission(username, filepath).CanWrite()
}

// CanGrant checks if a user has grant permission for a path
func (a *Authorizer) CanGrant(username string, filepath string) bool {
	return a.ResolvePermission(username, filepath).CanGrant()
}

// ResolvePermission returns the effective permission for a user on a path.
// It mirrors access.c _get_access: the user map, the user's group maps, and
// the default "*" map are walked together, component by component, with the
// nearest-ancestor "*" carried down as an inherited default. "No rule" (0) and
// explicit Revoked (-1) both mean no access and are normalized to Revoked.
func (a *Authorizer) ResolvePermission(username string, filepath string) Permission {
	if err := a.ensureFreshCache(); err != nil {
		logging.App.Debug("Cache refresh failed", "user", username, "path", filepath, "error", err)
		return Revoked
	}

	a.mu.RLock()
	accessMap := a.accessMap
	a.mu.RUnlock()
	if accessMap == nil {
		return Revoked
	}

	groups := a.resolveGroups(accessMap, username)
	perm := resolveAccess(accessMap, username, groups, splitPath(filepath))
	if perm < Read {
		// Undecided (0) and Revoked (-1) both deny.
		perm = Revoked
	}
	logging.App.Debug("Resolved permission", "user", username, "path", filepath, "permission", perm)
	return perm
}

// resolveAccess is a direct port of access.c _get_access.
func resolveAccess(accessMap map[string]interface{}, user string, groups []string, parts []string) Permission {
	// Collect the ordered list of maps to consider: the user's own map (if
	// any) first, then group maps, then the default "*" map. The user map is
	// only ever at index 0.
	maps := make([]map[string]interface{}, 0, len(groups)+2)
	if um, ok := accessMap[user].(map[string]interface{}); ok {
		maps = append(maps, um)
	}
	for _, g := range groups {
		if gm, ok := accessMap[g].(map[string]interface{}); ok {
			maps = append(maps, gm)
		}
	}
	if dm, ok := accessMap["*"].(map[string]interface{}); ok {
		maps = append(maps, dm)
	}

	mapc := len(maps)
	if mapc == 0 {
		return Revoked
	}

	// Per-map descent state and carried default (nearest ancestor "*").
	cur := make([]map[string]interface{}, mapc)
	dfls := make([]int, mapc)
	for j := range maps {
		cur[j] = maps[j]
		dfls[j] = starVal(maps[j])
	}

	// Walk the path. For each component, consult the maps in priority order;
	// the first map that yields a decided (non-zero) level wins that component
	// (earlier maps override later maps).
	j := 0
	for i, part := range parts {
		final := i == len(parts)-1
		for j = 0; j < mapc; j++ {
			dfls[j] = evalMap(part, cur, j, dfls[j], final)
			if dfls[j] != 0 {
				break
			}
		}
		if j >= mapc {
			j = mapc - 1 // no map decided this component; keep the last
		}
	}

	// Ruled access: for /d/<x> and /players/<x>, unless the map at index 0
	// decided (j == 0 with more than one map), a wizard has full access to
	// their own directory and everyone has read access to an "open" directory
	// and its contents.
	if len(parts) >= 2 && (parts[0] == "d" || parts[0] == "players") && (j != 0 || mapc == 1) {
		if parts[1] == user {
			return GrantGrant
		}
		if len(parts) >= 3 && parts[2] == "open" {
			return Read
		}
	}

	return Permission(dfls[j])
}

// evalMap is a direct port of access.c eval_map. It returns the access level
// for one path component in one map, and updates the map's descent state
// (cur[idx]) to the matched subtree, or nil once the map is exhausted.
func evalMap(part string, cur []map[string]interface{}, idx, dfl int, final bool) int {
	m := cur[idx]
	if m == nil { // map already exhausted; carry its default
		return dfl
	}

	// Start from this node's "*", or the inherited default if it has none.
	acc := starVal(m)
	if acc == 0 {
		acc = dfl
	}

	v, found := m[part]
	if !found {
		cur[idx] = nil // no deeper match in this map
		return acc
	}

	sub, isBranch := v.(map[string]interface{})
	if !isBranch {
		// Leaf: its value applies to this node and everything below it.
		cur[idx] = nil
		return permInt(v)
	}

	// Branch: decide this component's access, then descend.
	switch {
	case dfl == 0:
		acc = starVal(sub)
	case final:
		if d := dotVal(sub); d != 0 {
			acc = d
		} else {
			acc = dfl
		}
	default: // not the final component
		if s := starVal(sub); s != 0 {
			acc = s
		} else {
			acc = dfl
		}
	}
	cur[idx] = sub
	return acc
}

// resolveGroups returns the ordered groups for a user: explicit "?" groups (in
// order) followed by implicit level-based arch groups, matching query_groups.
func (a *Authorizer) resolveGroups(accessMap map[string]interface{}, username string) []string {
	groups := explicitGroups(accessMap, username)

	if user, err := a.characterData.LoadUser(username); err == nil {
		if _, ok := accessMap[GroupArchFull].(map[string]interface{}); ok && user.Level >= users.ARCHWIZARD {
			groups = append(groups, GroupArchFull)
		} else if _, ok := accessMap[GroupArchJunior].(map[string]interface{}); ok &&
			user.Level >= users.JUNIOR_ARCH && user.Level != users.ELDER {
			groups = append(groups, GroupArchJunior)
		}
	}
	return groups
}

// ResolveGroups returns all groups a user belongs to (explicit then implicit).
func (a *Authorizer) ResolveGroups(username string) []string {
	if err := a.ensureFreshCache(); err != nil {
		return []string{}
	}
	a.mu.RLock()
	accessMap := a.accessMap
	a.mu.RUnlock()
	if accessMap == nil {
		return []string{}
	}
	return a.resolveGroups(accessMap, username)
}

// GetExplicitGroups returns the explicit "?" groups a user belongs to.
func (a *Authorizer) GetExplicitGroups(username string) []string {
	if err := a.ensureFreshCache(); err != nil {
		return []string{}
	}
	a.mu.RLock()
	accessMap := a.accessMap
	a.mu.RUnlock()
	if accessMap == nil {
		return []string{}
	}
	return explicitGroups(accessMap, username)
}

// explicitGroups reads the user's "?" group list from the access map.
func explicitGroups(accessMap map[string]interface{}, username string) []string {
	um, ok := accessMap[username].(map[string]interface{})
	if !ok {
		return []string{}
	}
	raw, ok := um["?"].([]interface{})
	if !ok {
		return []string{}
	}
	groups := make([]string, 0, len(raw))
	for _, g := range raw {
		if s, ok := g.(string); ok {
			groups = append(groups, s)
		}
	}
	return groups
}

// refreshCache loads and validates fresh access data.
func (a *Authorizer) refreshCache() error {
	logging.App.Debug("Refreshing access cache")
	rawData, err := a.source.LoadAccessData()
	if err != nil {
		return fmt.Errorf("loading raw data: %w", err)
	}

	accessMap, err := loadAccessMap(rawData)
	if err != nil {
		return fmt.Errorf("loading access map: %w", err)
	}

	a.mu.Lock()
	a.accessMap = accessMap
	a.lastRefresh = time.Now()
	a.mu.Unlock()
	return nil
}

// ensureFreshCache refreshes the cache if the TTL has elapsed.
func (a *Authorizer) ensureFreshCache() error {
	a.mu.RLock()
	needsRefresh := a.accessMap == nil || time.Since(a.lastRefresh) >= a.cacheDuration
	a.mu.RUnlock()

	if needsRefresh {
		return a.refreshCache()
	}
	return nil
}

// starVal returns a node's "*" access level (0 if absent).
func starVal(m map[string]interface{}) int { return permInt(m["*"]) }

// dotVal returns a node's "." access level (0 if absent).
func dotVal(m map[string]interface{}) int { return permInt(m["."]) }

// permInt coerces a raw access value to an int (0 for absent/unexpected).
func permInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case Permission:
		return int(x)
	}
	return 0
}

// splitPath cleans a path and returns its components (dropping "" and ".").
func splitPath(p string) []string {
	raw := strings.Split(path.Clean(p), "/")
	parts := make([]string, 0, len(raw))
	for _, s := range raw {
		if s != "" && s != "." {
			parts = append(parts, s)
		}
	}
	return parts
}
