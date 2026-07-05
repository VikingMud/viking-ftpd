package authorization

import (
	"sync"
	"testing"
	"time"
)

// TestResolvePermissionConcurrentWithCacheRefresh drives ResolvePermission from
// many goroutines while the cache continuously refreshes (cacheDuration 0 forces
// a map swap on nearly every call). Run under -race, it fails if ResolvePermission
// reads the tree map without synchronizing against refreshCache's replacement.
func TestResolvePermissionConcurrentWithCacheRefresh(t *testing.T) {
	source := newMockUserSource()
	source.addUser("wizard1", 31)
	source.addUser("arch1", 45)

	auth := NewAuthorizer(newMockAccessSource(productionTree()), source, 0)

	const goroutines = 16
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			users := []string{"wizard1", "arch1", "nobody"}
			paths := []string{"/players/wizard1/file.c", "/d/Realm/room.c", "/tmp/x", "/"}
			for i := 0; i < iterations; i++ {
				u := users[(id+i)%len(users)]
				p := paths[i%len(paths)]
				auth.CanRead(u, p)
				auth.CanWrite(u, p)
				auth.ResolveGroups(u)
			}
		}(g)
	}
	wg.Wait()
}

// TestResolvePermissionSnapshotStability confirms a caller reading during a
// refresh still gets a coherent answer (no panic/torn map), exercised with a
// tight refresh interval and a concurrent forced refresh.
func TestResolvePermissionSnapshotStability(t *testing.T) {
	source := newMockUserSource()
	source.addUser("wizard1", 31)

	auth := NewAuthorizer(newMockAccessSource(productionTree()), source, time.Nanosecond)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = auth.refreshCache()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			auth.CanRead("wizard1", "/players/wizard1/x")
		}
	}()
	wg.Wait()
}
