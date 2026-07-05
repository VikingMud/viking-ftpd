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

// Authorizer handles access control and permissions with caching
type Authorizer struct {
	source        AccessSource
	characterData users.Source
	cacheDuration time.Duration

	mu          sync.RWMutex
	trees       map[string]*AccessTree
	lastRefresh time.Time
}

// NewAuthorizer creates a new Authorizer instance
func NewAuthorizer(source AccessSource, characterData users.Source, cacheDuration time.Duration) *Authorizer {
	return &Authorizer{
		source:        source,
		characterData: characterData,
		cacheDuration: cacheDuration,
		trees:         make(map[string]*AccessTree),
	}
}

// HasPermission checks if a user has the required permission for a path
func (a *Authorizer) HasPermission(username string, filepath string, requiredPerm Permission) bool {
	effectivePerm := a.ResolvePermission(username, filepath)
	return effectivePerm >= requiredPerm
}

// ResolvePermission returns the effective permission for a user on a path
func (a *Authorizer) ResolvePermission(username string, filepath string) Permission {
	if err := a.ensureFreshCache(); err != nil {
		logging.App.Debug("Cache refresh failed", "user", username, "path", filepath, "error", err)
		return Revoked
	}

	// Snapshot the tree map under the read lock. refreshCache replaces the
	// map wholesale rather than mutating it, so the captured reference is a
	// stable, immutable view even if a concurrent refresh swaps in a new map.
	a.mu.RLock()
	trees := a.trees
	a.mu.RUnlock()

	// Clean the path and split into parts
	parts := strings.Split(path.Clean(filepath), "/")
	if len(parts) > 0 && parts[0] == "" {
		parts = parts[1:]
	}
	// Handle root path specifically
	if len(parts) == 1 && parts[0] == "" {
		parts = []string{} // Empty array for root path
	}

	// Check implicit permissions first
	if implicitPerm, ok := a.resolveImplicitPermission(username, parts); ok {
		logging.App.Debug("Resolved implicit permission", "user", username, "path", filepath, "permission", implicitPerm)
		return implicitPerm
	}

	// Check user's direct permissions
	if tree, ok := trees[username]; ok {
		perm := a.resolveNodePermission(tree.Root, parts)
		if perm != Revoked {
			logging.App.Debug("Resolved direct permission", "user", username, "path", filepath, "permission", perm)
			return perm
		}
	}

	// Check all group permissions (both explicit and implicit)
	for _, group := range a.ResolveGroups(username) {
		if tree, ok := trees[group]; ok {
			perm := a.resolveNodePermission(tree.Root, parts)
			if perm != Revoked {
				logging.App.Debug("Resolved group permission", "user", username, "group", group, "path", filepath, "permission", perm)
				return perm
			}
		}
	}

	// Finally check default permissions
	if tree, ok := trees["*"]; ok {
		perm := a.resolveNodePermission(tree.Root, parts)
		logging.App.Debug("Using default permission", "user", username, "path", filepath, "permission", perm)
		return perm
	}

	logging.App.Debug("No permission found, defaulting to revoked", "user", username, "path", filepath)
	return Revoked
}

// ResolveGroups returns all groups that a user belongs to, including both
// explicit groups from the access tree and implicit groups based on character level.
func (a *Authorizer) ResolveGroups(username string) []string {
	if err := a.ensureFreshCache(); err != nil {
		return []string{}
	}

	// Get explicit groups
	groups := a.GetExplicitGroups(username)
	if groups == nil {
		groups = []string{}
	}

	// Add implicit groups
	implicitGroups := a.resolveImplicitGroups(username)
	if implicitGroups != nil {
		groups = append(groups, implicitGroups...)
	}

	return groups
}

// GetExplicitGroups returns the explicit groups a user belongs to from their access tree
func (a *Authorizer) GetExplicitGroups(username string) []string {
	if err := a.ensureFreshCache(); err != nil {
		return []string{}
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// Get user's tree
	tree, ok := a.trees[username]
	if !ok || tree == nil {
		return []string{}
	}

	// Groups are stored in the tree itself
	if tree.Groups == nil {
		return []string{}
	}
	return tree.Groups
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

// refreshCache loads fresh data from the source
func (a *Authorizer) refreshCache() error {
	logging.App.Debug("Refreshing access cache")
	rawData, err := a.source.LoadAccessData()
	if err != nil {
		logging.App.Debug("Failed to load access data", "error", err)
		return fmt.Errorf("loading raw data: %w", err)
	}

	trees, err := BuildAccessTrees(rawData)
	if err != nil {
		logging.App.Debug("Failed to build access trees", "error", err)
		return fmt.Errorf("building access trees: %w", err)
	}

	a.mu.Lock()
	a.trees = trees
	a.lastRefresh = time.Now()
	a.mu.Unlock()

	return nil
}

// ensureFreshCache checks if cache needs refresh
func (a *Authorizer) ensureFreshCache() error {
	a.mu.RLock()
	needsRefresh := time.Since(a.lastRefresh) >= a.cacheDuration
	a.mu.RUnlock()

	if needsRefresh {
		return a.refreshCache()
	}
	return nil
}

// resolveImplicitPermission returns any implicit permissions for a path and user
func (a *Authorizer) resolveImplicitPermission(username string, parts []string) (Permission, bool) {
	if len(parts) >= 2 && parts[0] == "players" {
		if parts[1] == username {
			return GrantGrant, true // Users always have GRANT_GRANT on their own directory
		}
		// Check for open directory at exactly level 3
		if len(parts) >= 3 && parts[2] == "open" && len(parts) == 3 {
			return Read, true // Everyone can read open directories at level 3
		}
	}
	return Revoked, false
}

// resolveImplicitGroups returns implicit groups based on character level
func (a *Authorizer) resolveImplicitGroups(username string) []string {
	user, err := a.characterData.LoadUser(username)
	if err != nil {
		return []string{}
	}

	groups := make([]string, 0)

	// Check if the groups exist in the access map before adding them
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Arch_full for archwizards and above
	if _, ok := a.trees[GroupArchFull]; ok && user.Level >= users.ARCHWIZARD {
		groups = append(groups, GroupArchFull)
	} else if _, ok := a.trees[GroupArchJunior]; ok && user.Level >= users.JUNIOR_ARCH && user.Level != users.ELDER {
		// Arch_junior for junior arches (except elders)
		groups = append(groups, GroupArchJunior)
	}

	return groups
}

// resolveNodePermission recursively checks permissions in a node
func (a *Authorizer) resolveNodePermission(node *AccessNode, pathParts []string) Permission {
	if node == nil {
		return Revoked
	}

	// At the target node (final node)
	if len(pathParts) == 0 {
		// At final node, dot access overrides star access
		if node.DotAccess != Revoked {
			return node.DotAccess
		}
		// No dot access, use star access
		return node.StarAccess
	}

	part := pathParts[0]
	rest := pathParts[1:]

	// Check for exact match in children
	if child, ok := node.Children[part]; ok {
		// Recursively check child permissions
		childPerm := a.resolveNodePermission(child, rest)
		// If child returns Revoked, that's final - don't fall back to star access
		return childPerm
	}

	// No matching child, use star access
	return node.StarAccess
}
