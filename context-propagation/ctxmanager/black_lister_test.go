package ctxmanager

import (
	"strings"
	"sync"
	"testing"
)

func resetSingleton(present bool, envVal string) {
	once = sync.Once{}
	globalBlackLister = nil
	once.Do(func() {
		raw := envVal
		if !present {
			raw = defaultInBlackList
		}
		var entries []string
		for _, entry := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(entry); trimmed != "" {
				entries = append(entries, trimmed)
			}
		}
		globalBlackLister = &contextBlackLister{blackListedContexts: entries}
	})
}

func TestIsBlackListed_Default_BuiltInUsed(t *testing.T) {
	resetSingleton(false, "")

	if !IsContextBlackListed("X-Channel-Request-Id") {
		t.Error("expected built-in default 'X-Channel-Request-Id' to be blacklisted when env is not set")
	}
}

func TestIsBlackListed_Default_CaseInsensitive(t *testing.T) {
	resetSingleton(false, "")

	for _, c := range []string{"x-channel-request-id", "X-CHANNEL-REQUEST-ID", "x-Channel-Request-Id"} {
		if !IsContextBlackListed(c) {
			t.Errorf("expected default built-in to be blacklisted case-insensitively, got false for %q", c)
		}
	}
}

func TestIsBlackListed_EnvOverridesDefault(t *testing.T) {
	resetSingleton(true, "X-Black-Listed-First,X-Black-Listed-Second")

	if IsContextBlackListed("X-Channel-Request-Id") {
		t.Error("expected built-in default to be absent when env is set")
	}
	if !IsContextBlackListed("X-Black-Listed-First") {
		t.Error("expected 'X-Black-Listed-First' to be blacklisted")
	}
	if !IsContextBlackListed("X-Black-Listed-Second") {
		t.Error("expected 'X-Black-Listed-Second' to be blacklisted")
	}
}

func TestIsBlackListed_EnvEmpty_NoEntries(t *testing.T) {
	resetSingleton(true, "")

	if IsContextBlackListed("X-Channel-Request-Id") {
		t.Error("expected built-in default to be absent when env is set to empty")
	}
	if IsContextBlackListed("X-Black-Listed-First") {
		t.Error("expected no entries when env is set to empty string")
	}
}

func TestIsBlackListed_ExactMatch(t *testing.T) {
	resetSingleton(true, "X-Black-Listed-First,X-Black-Listed-Second")

	for _, name := range []string{"X-Black-Listed-First", "X-Black-Listed-Second"} {
		if !IsContextBlackListed(name) {
			t.Errorf("expected %q to be blacklisted", name)
		}
	}
}

func TestIsBlackListed_CaseInsensitive(t *testing.T) {
	resetSingleton(true, "X-Black-Listed-First,X-Black-Listed-Second")

	for _, c := range []string{"x-black-listed-first", "X-BLACK-LISTED-FIRST", "X-Black-Listed-First",
		"x-black-listed-second", "X-BLACK-LISTED-SECOND", "X-Black-Listed-Second"} {
		if !IsContextBlackListed(c) {
			t.Errorf("expected %q to be blacklisted (case-insensitive)", c)
		}
	}
}

func TestIsBlackListed_NotInList(t *testing.T) {
	resetSingleton(true, "X-Black-Listed-First,X-Black-Listed-Second")

	if IsContextBlackListed("X-Black-Listed-Third") {
		t.Error("expected 'X-Black-Listed-Third' not to be blacklisted")
	}
	if IsContextBlackListed("") {
		t.Error("expected empty string not to be blacklisted")
	}
}

func TestIsBlackListed_WhitespaceTrimming(t *testing.T) {
	resetSingleton(true, "  X-Black-Listed-First , X-Black-Listed-Second  ")

	for _, name := range []string{"X-Black-Listed-First", "X-Black-Listed-Second"} {
		if !IsContextBlackListed(name) {
			t.Errorf("expected %q to be blacklisted after whitespace trimming", name)
		}
	}
}
