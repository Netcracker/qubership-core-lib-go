package ctxmanager

import (
	"sync"
	"testing"
)

func resetSingleton(optionallyEnabled []string) {
	once = sync.Once{}
	globalContextRestricter = nil
	once.Do(func() {
		globalContextRestricter = newContextRestricter(optionallyEnabled)
	})
}

func TestIsBlackListed_Default_BuiltInUsed(t *testing.T) {
	resetSingleton(nil)

	if !IsContextRestricted("X-Channel-Request-Id") {
		t.Error("expected built-in default 'X-Channel-Request-Id' to be restricted when config is not set")
	}
}

func TestIsBlackListed_Default_CaseInsensitive(t *testing.T) {
	resetSingleton(nil)

	for _, c := range []string{"x-channel-request-id", "X-CHANNEL-REQUEST-ID", "x-Channel-Request-Id"} {
		if !IsContextRestricted(c) {
			t.Errorf("expected default built-in to be restricted case-insensitively, got false for %q", c)
		}
	}
}

func TestOptionalHeaders_UnrestrictDefaultRestricted(t *testing.T) {
	resetSingleton([]string{"X-Channel-Request-Id"})

	if IsContextRestricted("X-Channel-Request-Id") {
		t.Errorf("expected 'X-Channel-Request-Id' to be unrestricted when listed in %s", optionalHeadersEnabledConfigKey)
	}
}

func TestOptionalHeaders_EmptySlice_DefaultRestrictedRemains(t *testing.T) {
	resetSingleton([]string{})

	if !IsContextRestricted("X-Channel-Request-Id") {
		t.Errorf("expected 'X-Channel-Request-Id' to remain restricted when %s is empty", optionalHeadersEnabledConfigKey)
	}
}

func TestOptionalHeaders_CaseInsensitive(t *testing.T) {
	for _, optVal := range []string{"x-channel-request-id", "X-CHANNEL-REQUEST-ID", "x-Channel-Request-Id"} {
		resetSingleton([]string{optVal})
		if IsContextRestricted("X-Channel-Request-Id") {
			t.Errorf("expected 'X-Channel-Request-Id' to be unrestricted when optional value is %q (case-insensitive match)", optVal)
		}
	}
}

func TestOptionalHeaders_UnknownHeader_DoesNotUnrestrict(t *testing.T) {
	resetSingleton([]string{"X-Some-Other-Header"})

	if !IsContextRestricted("X-Channel-Request-Id") {
		t.Error("expected 'X-Channel-Request-Id' to remain restricted when an unrelated optional header is set")
	}
}

func TestIsBlackListed_NotInDefaultList(t *testing.T) {
	resetSingleton(nil)

	if IsContextRestricted("X-Request-Id") {
		t.Error("expected 'X-Request-Id' not to be restricted (not in default restricted list)")
	}
	if IsContextRestricted("") {
		t.Error("expected empty string not to be restricted")
	}
}
