// Session storage round-trips lifecycle state, replaces sessions and run history atomically, and serializes complete
// read-modify-write cycles across concurrent writers.
package session

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func sessionIDFor(n int) string { return fmt.Sprintf("s-%012x", n) }

func testSessionStore(t *testing.T) Store {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(testutil.Database(t), dir, Schema)
	testutil.Check(t, err)
	t.Cleanup(func() { testutil.Check(t, database.Close()) })
	return Store{Dir: dir, Database: database}
}

func TestStoreRoundTripsSessionsAndRuns(t *testing.T) {
	store := testSessionStore(t)
	session := pendingSession("s-012345abcdef", "delta", "101")
	run := runRecord{Run: Run{SessionID: session.ID, Seq: 1, Alias: "delta", EndedAt: time.Unix(2, 0).UTC()}, Owner: testPrincipal}

	testutil.Check(t, store.locked(func(current *state) error {
		current.Sessions[session.ID] = &session
		current.Runs = append(current.Runs, run)
		return store.save(current)
	}))

	testutil.Check(t, store.locked(func(current *state) error {
		got, ok := current.Sessions[session.ID]
		if !ok || got.Alias != "delta" || got.JobID != "101" {
			t.Fatalf("session did not round-trip: %+v, ok=%v", got, ok)
		}
		if len(current.Runs) != 1 || current.Runs[0].SessionID != session.ID || !current.Runs[0].EndedAt.Equal(run.EndedAt) {
			t.Fatalf("run did not round-trip: %+v", current.Runs)
		}
		return nil
	}))
}

func TestStoreSaveIsAtomic(t *testing.T) {
	store := testSessionStore(t)
	committed := pendingSession("s-111111111111", "delta", "1")
	testutil.Check(t, store.locked(func(current *state) error {
		current.Sessions[committed.ID] = &committed
		return store.save(current)
	}))

	dup := runRecord{Run: Run{SessionID: "s-222222222222", Seq: 1, EndedAt: time.Unix(1, 0).UTC()}}
	if err := store.locked(func(current *state) error {
		delete(current.Sessions, committed.ID)
		current.Runs = append(current.Runs, dup, dup)
		return store.save(current)
	}); err == nil {
		t.Fatal("a save with a duplicate run key was accepted")
	}

	testutil.Check(t, store.locked(func(current *state) error {
		if _, ok := current.Sessions[committed.ID]; !ok {
			t.Fatal("a failed save discarded the previously committed session")
		}
		if len(current.Runs) != 0 {
			t.Fatalf("a failed save left partial run rows: %+v", current.Runs)
		}
		return nil
	}))
}

func TestStoreConcurrentWritersSerialize(t *testing.T) {
	store := testSessionStore(t)
	const writers = 20
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(n int) {
			defer wg.Done()
			session := pendingSession(sessionIDFor(n), "delta", "1")
			testutil.Check(t, store.locked(func(current *state) error {
				current.Sessions[session.ID] = &session
				return store.save(current)
			}))
		}(i)
	}
	wg.Wait()

	testutil.Check(t, store.locked(func(current *state) error {
		if len(current.Sessions) != writers {
			t.Fatalf("concurrent writers left %d sessions, want %d", len(current.Sessions), writers)
		}
		return nil
	}))
}
