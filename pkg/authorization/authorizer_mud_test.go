package authorization

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mmcdole/viking-ftpd/pkg/lpc"
	"github.com/mmcdole/viking-ftpd/pkg/users"
)

// loadRealAuthorizer builds an Authorizer over the production access.txt shipped
// in resources/. That file is the bare access_map mapping, so it is wrapped as
// an object field before parsing.
func loadRealAuthorizer(t *testing.T, testUsers map[string]int) *Authorizer {
	t.Helper()
	raw, err := os.ReadFile("../../resources/access.txt")
	if err != nil {
		t.Skipf("no resources/access.txt: %v", err)
	}
	res, err := lpc.NewObjectParser(false).ParseObject("access_map " + strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("parse access.txt: %v", err)
	}

	usrc := users.NewMemorySource()
	for name, level := range testUsers {
		usrc.AddUser(&users.User{Username: name, Level: level, PasswordHash: "x"})
	}
	auth := NewAuthorizer(&mockAccessSource{tree: res.Object}, usrc, time.Hour)
	if err := auth.refreshCache(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return auth
}

// TestRealAccessData asserts specific decisions against the production access
// map. The cases marked "(was wrong)" are the divergences from the MUD that
// this change fixes; they resolved differently before the resolver rewrite.
func TestRealAccessData(t *testing.T) {
	auth := loadRealAuthorizer(t, map[string]int{
		"anon":       users.WIZARD,      // no map
		"dios":       users.WIZARD,      // map: {"*":5, "players":{"gaia":1}}
		"drake":      users.WIZARD,      // map: {"*":5}
		"preman":     users.WIZARD,      // map: explicit players/cryzeck/open:3
		"fullarch":   users.ARCHWIZARD,  // no map, implicit Arch_full ({"*":4})
		"juniorarch": users.JUNIOR_ARCH, // no map, implicit Arch_junior ({"d":3,"players":3})
	})

	cases := []testCase{
		// Read-by-default from the real root "*":1.
		{"root_readable", "anon", "/", Read},
		{"tmp_writable", "anon", "/tmp", Write},
		{"data_private", "anon", "/data", Revoked},
		{"accounts_private", "anon", "/accounts", Revoked},
		{"log_readable", "anon", "/log/foo", Read},
		{"log_driver_private", "anon", "/log/Driver", Revoked},

		// Inherited "*" reaches star-less subtrees (was wrong: Revoked).
		{"com_readable", "anon", "/com", Read},
		{"com_a_readable", "anon", "/com/a", Read},
		{"com_a_law_revoked", "anon", "/com/a/law", Revoked}, // explicit -1

		// Open directories: the dir and its contents are world-readable
		// (was wrong: contents Revoked).
		{"open_dir", "anon", "/players/drake/open", Read},
		{"open_contents", "anon", "/players/drake/open/file.c", Read},
		{"open_d_domain", "anon", "/d/Foo/open", Read},
		{"open_d_contents", "anon", "/d/Foo/open/x", Read},

		// Blanket "*" grants reach into subdirectories (was wrong: Revoked).
		{"wildcard_players", "dios", "/players/knubo", GrantGrant},
		{"wildcard_deep", "dios", "/players/cryzeck/sms", GrantGrant},
		{"wildcard_domain", "drake", "/d/Foo/room.c", GrantGrant},
		{"wildcard_specific", "dios", "/players/gaia", Read}, // dios's explicit players/gaia:1 overrides *:5

		// A user's explicit grant on someone's open dir wins over the implicit
		// open read (was wrong: downgraded to Read).
		{"explicit_over_open", "preman", "/players/cryzeck/open", Write},

		// Own directory is full access.
		{"own_dir", "dios", "/players/dios/workroom.c", GrantGrant},

		// Implicit arch groups grant across the tree.
		{"fullarch_anywhere", "fullarch", "/players/knubo/secret", GrantWrite},
		{"juniorarch_players", "juniorarch", "/players/knubo", Write},
		{"juniorarch_com", "juniorarch", "/com", Read}, // via default "*":1, not the group
	}
	runTests(t, auth, cases)
}
