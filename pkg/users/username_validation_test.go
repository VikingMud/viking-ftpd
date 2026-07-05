package users

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadUserRejectsTraversalNames ensures usernames that could escape the
// character directory are rejected with ErrUserNotFound before any file access.
// A planted file outside the sharded layout must never be reachable.
func TestLoadUserRejectsTraversalNames(t *testing.T) {
	root := t.TempDir()

	// Plant a valid-looking character file one level above the character root,
	// which a traversal username would otherwise reach.
	outside := filepath.Join(root, "secret.o")
	if err := os.WriteFile(outside, []byte(`password "x"`+"\nlevel 50\n"), 0644); err != nil {
		t.Fatal(err)
	}
	charDir := filepath.Join(root, "chars")
	if err := os.MkdirAll(charDir, 0755); err != nil {
		t.Fatal(err)
	}

	source := NewFileSource(charDir)

	bad := []string{
		"../secret",
		"../../secret",
		"a/../../secret",
		"foo/bar",
		"foo.bar",
		`foo\bar`,
		"",
		".",
		"..",
		"foo bar",
	}
	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := source.LoadUser(name)
			if err != ErrUserNotFound {
				t.Errorf("LoadUser(%q) = %v, want ErrUserNotFound", name, err)
			}
		})
	}
}

// TestLoadUserAcceptsValidNames confirms ordinary names still load.
func TestLoadUserAcceptsValidNames(t *testing.T) {
	root := t.TempDir()
	source := NewFileSource(root)

	for _, name := range []string{"alice", "Bob", "wiz_99", "a-b", "x"} {
		dir := filepath.Join(root, strings.ToLower(name[0:1]))
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".o"), []byte(`password "h"`+"\nlevel 1\n"), 0644); err != nil {
			t.Fatal(err)
		}
		u, err := source.LoadUser(name)
		if err != nil {
			t.Errorf("LoadUser(%q) unexpected error: %v", name, err)
			continue
		}
		if u.Username != name {
			t.Errorf("LoadUser(%q).Username = %q", name, u.Username)
		}
	}
}
