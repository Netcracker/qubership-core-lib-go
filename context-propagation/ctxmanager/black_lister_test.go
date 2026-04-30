package ctxmanager

import (
	"strings"
	"sync"
	"testing"
)

func newBlackLister(entries ...string) *contextBlackLister {
	return &contextBlackLister{blackListedContexts: entries}
}

func TestContextBlackLister_EmptyList(t *testing.T) {
	cbl := newBlackLister()
	if cbl.isBlackListed("anything") {
		t.Error("expected empty blacklist to return false for any input")
	}
}

func TestContextBlackLister_SingleEntry(t *testing.T) {
	cbl := newBlackLister("X-Only-Header")
	if !cbl.isBlackListed("X-Only-Header") {
		t.Error("expected single entry to be blacklisted")
	}
	if cbl.isBlackListed("X-Other-Header") {
		t.Error("expected non-matching header not to be blacklisted")
	}
}

func TestContextBlackLister_CaseInsensitive(t *testing.T) {
	cbl := newBlackLister("X-My-Header")
	for _, variant := range []string{"x-my-header", "X-MY-HEADER", "X-My-Header", "X-mY-hEaDeR"} {
		if !cbl.isBlackListed(variant) {
			t.Errorf("expected case-insensitive match for %q", variant)
		}
	}
}

func TestContextBlackLister_EmptyStringNotBlacklisted(t *testing.T) {
	cbl := newBlackLister("X-My-Header")
	if cbl.isBlackListed("") {
		t.Error("expected empty string not to be blacklisted")
	}
}

// --- Dynamic update tests ---

func TestDynamicUpdate_BlacklistChanges(t *testing.T) {
	cbl := newBlackLister("X-Original-Header")

	if !cbl.isBlackListed("X-Original-Header") {
		t.Error("expected original header to be blacklisted before update")
	}

	// Simulate config reload
	cbl.mu.Lock()
	cbl.blackListedContexts = []string{"X-New-Header"}
	cbl.mu.Unlock()

	if cbl.isBlackListed("X-Original-Header") {
		t.Error("expected original header NOT to be blacklisted after update")
	}
	if !cbl.isBlackListed("X-New-Header") {
		t.Error("expected new header to be blacklisted after update")
	}
}

func TestDynamicUpdate_ClearList(t *testing.T) {
	cbl := newBlackLister("X-Some-Header")

	cbl.mu.Lock()
	cbl.blackListedContexts = nil
	cbl.mu.Unlock()

	if cbl.isBlackListed("X-Some-Header") {
		t.Error("expected no entries after clearing list")
	}
}

func TestConcurrentReadsAreSafe(t *testing.T) {
	cbl := newBlackLister("X-Concurrent-Header")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cbl.isBlackListed("X-Concurrent-Header")
		}()
	}
	wg.Wait()
}

func TestConcurrentReadWriteAreSafe(t *testing.T) {
	cbl := newBlackLister("X-Init-Header")
	var wg sync.WaitGroup

	// 50 concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cbl.isBlackListed("X-Init-Header")
		}()
	}

	// 10 concurrent writers (simulating config reloads)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			newEntries := []string{"X-Updated-Header"}
			cbl.mu.Lock()
			cbl.blackListedContexts = newEntries
			cbl.mu.Unlock()
		}(i)
	}

	wg.Wait()
}

func TestIsBlackListed_LargeList(t *testing.T) {
	entries := make([]string, 50)
	for i := range entries {
		entries[i] = strings.Repeat("X", i+1) + "-Header"
	}
	cbl := &contextBlackLister{blackListedContexts: entries}

	// First, middle, last should all match
	for _, name := range []string{entries[0], entries[24], entries[49]} {
		if !cbl.isBlackListed(name) {
			t.Errorf("expected %q to be blacklisted in large list", name)
		}
	}

	if cbl.isBlackListed("Not-In-List") {
		t.Error("expected 'Not-In-List' not to be blacklisted")
	}
}
