package authorization

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/mmcdole/viking-ftpd/pkg/users"
)

type mockUserSource struct {
	users map[string]*users.User
}

func newMockUserSource() *mockUserSource {
	return &mockUserSource{
		users: make(map[string]*users.User),
	}
}

func (m *mockUserSource) LoadUser(username string) (*users.User, error) {
	user, ok := m.users[username]
	if !ok {
		return nil, users.ErrUserNotFound
	}
	return user, nil
}

func (m *mockUserSource) addUser(username string, level int) {
	m.users[username] = &users.User{
		Username: username,
		Level:    level,
	}
}

type mockAccessSource struct {
	tree map[string]interface{}
}

func newMockAccessSource(tree map[string]interface{}) *mockAccessSource {
	return &mockAccessSource{tree: tree}
}

func (m *mockAccessSource) LoadAccessData() (map[string]interface{}, error) {
	return m.tree, nil
}

// runTests is a helper function to run permission test cases
type testCase struct {
	name     string
	username string
	path     string
	want     Permission
}

func runTests(t *testing.T, auth *Authorizer, cases []testCase) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auth.ResolvePermission(tc.username, tc.path)
			if got != tc.want {
				t.Errorf("ResolvePermission(%q, %q) = %v, want %v",
					tc.username, tc.path, got, tc.want)
			}
		})
	}
}

// productionTree returns a simplified version of the MUD's access tree structure
func productionTree() map[string]interface{} {
	return map[string]interface{}{
		"access_map": map[string]interface{}{
			"*": map[string]interface{}{
				".":          Read, // Everyone can read root directory
				"*":          Revoked,
				"accounts":   Revoked, // Private directory
				"characters": Revoked, // Private directory
				"data": map[string]interface{}{
					"*": Revoked, // Private directory
				},
				"log": map[string]interface{}{
					"*":      Read,
					"Driver": Revoked,
				},
				"players": map[string]interface{}{
					".": Read,    // READ on /players directory itself
					"*": Revoked, // REVOKED access to all player directories
				},
				"tmp": Write,
			},
			// Domain wizard with specific area access
			"wizard1": map[string]interface{}{
				"d": map[string]interface{}{
					"MyRealm": Write,
					"SharedRealm": map[string]interface{}{
						".": Write,
						"*": Read,
					},
				},
			},
			// Arch groups
			"Arch_full": map[string]interface{}{
				".": GrantGrant,
				"*": GrantGrant,
			},
			"Arch_junior": map[string]interface{}{
				".":      GrantWrite,
				"*":      GrantWrite,
				"secure": Write,
			},
		},
	}
}

// coreTree returns a minimal tree for testing basic permission concepts
func coreTree() map[string]interface{} {
	return map[string]interface{}{
		"access_map": map[string]interface{}{
			"*": map[string]interface{}{
				".": Read,
				"*": Revoked,
				"public": map[string]interface{}{
					".": Read,
					"*": Read,
				},
				// Truly private - no access at all
				"private": map[string]interface{}{
					".": Revoked,
					"*": Revoked,
				},
				// Restricted - can see but not enter
				"restricted": map[string]interface{}{
					".": Read,
					"*": Revoked,
				},
				// Test inheritance - star permission with no dot at lower level
				"inherit": map[string]interface{}{
					"*": Write, // This should be inherited by subdirs
				},
				// Test precedence between different levels
				"mixed": map[string]interface{}{
					"*": Write,
					"sub": map[string]interface{}{
						"*": Read, // This should override parent's Write
					},
					"deep": map[string]interface{}{
						"*": GrantRead,
						"subsub": map[string]interface{}{
							"*": Write, // Test multi-level precedence
						},
					},
				},
				// Test different permission levels between dot and star
				"levels": map[string]interface{}{
					".": GrantWrite,
					"*": Write,
					"sub": map[string]interface{}{
						".": Write,
						"*": GrantRead,
					},
				},
			},
			// User-specific overrides
			"user": map[string]interface{}{
				"override": Write, // Simple override of default Revoked
				"special": map[string]interface{}{
					".": Write,
					"*": Read,
				},
			},
		},
	}
}

// groupTree returns a tree focused on testing group membership and inheritance
func groupTree() map[string]interface{} {
	return map[string]interface{}{
		"access_map": map[string]interface{}{
			"*": map[string]interface{}{
				".": Read,
				"*": Revoked,
			},
			"Group1": map[string]interface{}{
				"area1": Write,
			},
			"Group2": map[string]interface{}{
				"area2": GrantRead,
			},
			"user1": map[string]interface{}{
				"?": []interface{}{"Group1", "Group2"}, // Member of both groups
			},
			"user2": map[string]interface{}{
				"?": []interface{}{"Group2"}, // Member of Group2 only
			},
		},
	}
}

func TestProductionExample(t *testing.T) {
	// Create mock user source
	source := newMockUserSource()
	source.addUser("wizard1", users.WIZARD)

	auth := NewAuthorizer(newMockAccessSource(productionTree()), source, time.Hour)

	t.Run("DefaultAccess", func(t *testing.T) {
		cases := []testCase{
			// Root resolves to the default map's "*" (here Revoked). Real
			// access.txt uses "*":1 so root is readable — see the real-data
			// test in authorizer_mud_test.go.
			{"root_access", "anonymous", "/", Revoked},
			{"accounts_denied", "anonymous", "/accounts", Revoked},     // Accounts dir is private
			{"characters_denied", "anonymous", "/characters", Revoked}, // Character data is private
			{"data_denied", "anonymous", "/data/test", Revoked},        // Data dir is private
			{"log_readable", "anonymous", "/log/test.log", Read},       // Logs are readable except Driver
			{"log_driver_denied", "anonymous", "/log/Driver", Revoked}, // Driver logs are private
			{"tmp_writable", "anonymous", "/tmp", Write},               // Temp dir is writable by all
		}
		runTests(t, auth, cases)
	})

	t.Run("DomainAccess", func(t *testing.T) {
		cases := []testCase{
			// Domain wizard permissions
			{"realm_write", "wizard1", "/d/MyRealm/room.c", Write}, // Full write in own realm
			// wizard1's map has no "*" along this path, so the inherited
			// default is 0 and the MUD uses the node's "*" (Read), not "."
			// (Write), even for the directory itself.
			{"shared_realm_root", "wizard1", "/d/SharedRealm", Read},
			{"shared_realm_files", "wizard1", "/d/SharedRealm/room.c", Read}, // Only read in shared files
		}
		runTests(t, auth, cases)
	})
}

func TestCorePermissions(t *testing.T) {
	// Create mock user source
	source := newMockUserSource()
	source.addUser("user", users.WIZARD)      // Use WIZARD level for user-specific permissions
	source.addUser("anonymous", users.WIZARD) // Use WIZARD for testing basic permissions

	auth := NewAuthorizer(newMockAccessSource(coreTree()), source, time.Hour)
	if err := auth.refreshCache(); err != nil {
		t.Fatalf("Failed to refresh cache: %v", err)
	}

	t.Run("DotVsStar", func(t *testing.T) {
		cases := []testCase{
			{"root_dot", "anonymous", "/", Revoked},            // Root resolves to default "*" (Revoked here); real data uses "*":1
			{"root_star", "anonymous", "/unknown", Revoked},    // Unknown paths are denied
			{"public_dot", "anonymous", "/public", Read},       // Can read public dir
			{"public_star", "anonymous", "/public/file", Read}, // Can read files in public

			// Private directory - no access at all
			{"private_dot", "anonymous", "/private", Revoked},       // Can't even see private dir
			{"private_star", "anonymous", "/private/file", Revoked}, // Can't access private files

			// Restricted - can see but not enter
			{"restricted_dot", "anonymous", "/restricted", Read},          // Can see restricted dir
			{"restricted_star", "anonymous", "/restricted/file", Revoked}, // But can't access contents
		}
		runTests(t, auth, cases)
	})

	t.Run("PermissionInheritance", func(t *testing.T) {
		cases := []testCase{
			{"inherit_star", "anonymous", "/inherit/file", Write},            // Star permission applies to files
			{"inherit_subdir", "anonymous", "/inherit/sub", Write},           // Star permission applies to subdirs
			{"inherit_subdir_file", "anonymous", "/inherit/sub/file", Write}, // Star permission applies at any depth
		}
		runTests(t, auth, cases)
	})

	t.Run("PermissionPrecedence", func(t *testing.T) {
		cases := []testCase{
			{"mixed_root_file", "anonymous", "/mixed/file", Write},           // Gets parent's * permission
			{"mixed_sub_file", "anonymous", "/mixed/sub/file", Read},         // Subdir * overrides parent
			{"mixed_deep_file", "anonymous", "/mixed/deep/file", GrantRead},  // Deeper permission wins
			{"mixed_deepest", "anonymous", "/mixed/deep/subsub/file", Write}, // Deepest level always wins
		}
		runTests(t, auth, cases)
	})

	t.Run("MixedPermissionLevels", func(t *testing.T) {
		cases := []testCase{
			{"levels_dot", "anonymous", "/levels", GrantWrite},              // Dot can have higher permission
			{"levels_file", "anonymous", "/levels/file", Write},             // Star has its own permission
			{"levels_sub_dot", "anonymous", "/levels/sub", Write},           // Subdir dot permission
			{"levels_sub_file", "anonymous", "/levels/sub/file", GrantRead}, // Subdir star can be higher
		}
		runTests(t, auth, cases)
	})

	t.Run("UserOverrides", func(t *testing.T) {
		cases := []testCase{
			{"simple_override", "user", "/override", Write}, // User overrides default Revoked
			// No inherited default along this path, so "special" itself uses
			// its "*" (Read), not its "." (Write).
			{"special_dot", "user", "/special", Read},
			{"special_star", "user", "/special/file", Read}, // User-specific star permission
		}
		runTests(t, auth, cases)
	})
}

func TestGroupPermissions(t *testing.T) {
	// Create mock user source with test users - use WIZARD level since they need file access
	source := newMockUserSource()
	source.addUser("user1", users.WIZARD) // WIZARD level for group membership tests
	source.addUser("user2", users.WIZARD) // WIZARD level for group membership tests

	auth := NewAuthorizer(newMockAccessSource(groupTree()), source, time.Hour)
	if err := auth.refreshCache(); err != nil {
		t.Fatalf("Failed to refresh cache: %v", err)
	}

	t.Run("SingleGroup", func(t *testing.T) {
		cases := []testCase{
			{"area2_access", "user2", "/area2", GrantRead}, // Member of Group2 gets its permissions
			{"area1_denied", "user2", "/area1", Revoked},   // No access to Group1's area
		}
		runTests(t, auth, cases)
	})

	t.Run("MultipleGroups", func(t *testing.T) {
		cases := []testCase{
			{"area1_access", "user1", "/area1", Write},     // Gets Write from Group1
			{"area2_access", "user1", "/area2", GrantRead}, // Gets GrantRead from Group2
		}
		runTests(t, auth, cases)
	})
}

func TestImplicitPermissions(t *testing.T) {
	// Mock user source with various levels
	source := newMockUserSource()
	source.addUser("arch", users.ARCHWIZARD)    // Level 45
	source.addUser("junior", users.JUNIOR_ARCH) // Level 40
	source.addUser("elder", users.ELDER)        // Level 42
	source.addUser("wizard", users.WIZARD)      // Level 31

	auth := NewAuthorizer(newMockAccessSource(productionTree()), source, time.Hour)
	if err := auth.refreshCache(); err != nil {
		t.Fatalf("Failed to refresh cache: %v", err)
	}

	t.Run("PlayerDirectories", func(t *testing.T) {
		cases := []testCase{
			// Own directory access
			{"wizard-own", "wizard", "/players/wizard", GrantGrant},
			{"wizard-own-deep", "wizard", "/players/wizard/deep/path", GrantGrant},

			// Other directory access
			{"wizard-other", "wizard", "/players/arch", Revoked},
			{"wizard-open", "wizard", "/players/arch/open", Read},

			// The "open" rule grants read to the open dir AND its contents
			// (depth >= 3), but only when parts[2] == "open".
			{"open-subdir", "wizard", "/players/arch/open/subdir", Read},
			{"not-open", "wizard", "/players/arch/not_open", Revoked},
			{"deep-open", "wizard", "/players/arch/deep/open", Revoked}, // "open" not at parts[2]

			// Home directory trumps group permissions
			{"home-trumps-group", "arch", "/players/arch/doc.txt", GrantGrant},   // Even with doc group, home dir wins
			{"home-trumps-domain", "wizard", "/players/wizard/open", GrantGrant}, // Even with domain access, home dir wins
		}
		runTests(t, auth, cases)
	})

	t.Run("ImplicitGroups", func(t *testing.T) {
		cases := []testCase{
			// Arch_full group (level 45+)
			{"arch-root", "arch", "/", GrantGrant},
			{"arch-secure", "arch", "/secure", GrantGrant},
			{"arch-domains", "arch", "/domains", GrantGrant},

			// Arch_junior group (level 40-44, except elder)
			{"junior-root", "junior", "/", GrantWrite},
			{"junior-secure", "junior", "/secure", Write},
			{"junior-domains", "junior", "/domains", GrantWrite},

			// Elder (level 42) should not get junior arch permissions. Root
			// resolves to the default "*" (Revoked here); real data uses "*":1.
			{"elder-root", "elder", "/", Revoked},
			{"elder-secure", "elder", "/secure", Revoked},
			{"elder-domains", "elder", "/domains", Revoked},

			// Regular wizard (level 31)
			{"wizard-root", "wizard", "/", Revoked},
			{"wizard-secure", "wizard", "/secure", Revoked},
			{"wizard-domains", "wizard", "/domains", Revoked},
		}
		runTests(t, auth, cases)
	})
}

func TestGroupMembership(t *testing.T) {
	// Mock user source with various levels
	source := newMockUserSource()
	source.addUser("arch", users.ARCHWIZARD)    // Level 45
	source.addUser("junior", users.JUNIOR_ARCH) // Level 40
	source.addUser("elder", users.ELDER)        // Level 42
	source.addUser("wizard", users.WIZARD)      // Level 31

	// Create a test access tree that includes explicit group assignments
	testTree := map[string]interface{}{
		"access_map": map[string]interface{}{
			"wizard": map[string]interface{}{
				"?": []interface{}{"Wiz_domain", "Wiz_qc"},
			},
			"junior": map[string]interface{}{
				"?": []interface{}{"Wiz_domain"},
			},
			// Arch groups
			"Arch_full": map[string]interface{}{
				".": GrantGrant,
				"*": GrantGrant,
			},
			"Arch_junior": map[string]interface{}{
				".":      GrantWrite,
				"*":      GrantWrite,
				"secure": Write,
			},
		},
	}

	auth := NewAuthorizer(newMockAccessSource(testTree), source, time.Hour)
	if err := auth.refreshCache(); err != nil {
		t.Fatalf("Failed to refresh cache: %v", err)
	}

	tests := []struct {
		name     string
		username string
		want     []string
	}{
		{
			name:     "arch gets implicit full",
			username: "arch",
			want:     []string{"Arch_full"},
		},
		{
			name:     "junior gets implicit junior and explicit domain",
			username: "junior",
			want:     []string{"Arch_junior", "Wiz_domain"},
		},
		{
			name:     "elder gets no groups",
			username: "elder",
			want:     []string{},
		},
		{
			name:     "wizard gets only explicit groups",
			username: "wizard",
			want:     []string{"Wiz_domain", "Wiz_qc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.ResolveGroups(tt.username)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ResolveGroups(%q) = %v (type %T), want %v (type %T)",
					tt.username, got, got, tt.want, tt.want)
			}
		})
	}
}
