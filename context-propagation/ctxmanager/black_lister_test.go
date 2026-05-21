package ctxmanager

import (
	"sync"
	"testing"
)

func resetSingleton(optionallyEnabled []string) {
	once = sync.Once{}
	globalBlackLister = nil
	once.Do(func() {
		globalBlackLister = newBlackLister(optionallyEnabled)
	})
}

func TestIsBlackListed_Default_BuiltInUsed(t *testing.T) {
	resetSingleton(nil)

	if !IsContextBlackListed("X-Channel-Request-Id") {
		t.Error("expected built-in default 'X-Channel-Request-Id' to be blocked when config is not set")
	}
}

func TestIsBlackListed_Default_CaseInsensitive(t *testing.T) {
	resetSingleton(nil)

	for _, c := range []string{"x-channel-request-id", "X-CHANNEL-REQUEST-ID", "x-Channel-Request-Id"} {
		if !IsContextBlackListed(c) {
			t.Errorf("expected default built-in to be blocked case-insensitively, got false for %q", c)
		}
	}
}

func TestOptionalHeaders_UnblocksDefaultBlocked(t *testing.T) {
	resetSingleton([]string{"X-Channel-Request-Id"})

	if IsContextBlackListed("X-Channel-Request-Id") {
		t.Error("expected 'X-Channel-Request-Id' to be unblocked when listed in context.propagation.headers.enable.optional")
	}
}

func TestOptionalHeaders_EmptySlice_DefaultBlockedRemains(t *testing.T) {
	resetSingleton([]string{})

	if !IsContextBlackListed("X-Channel-Request-Id") {
		t.Error("expected 'X-Channel-Request-Id' to remain blocked when context.propagation.headers.enable.optional is empty")
	}
}

func TestOptionalHeaders_CaseInsensitive(t *testing.T) {
	for _, optVal := range []string{"x-channel-request-id", "X-CHANNEL-REQUEST-ID", "x-Channel-Request-Id"} {
		resetSingleton([]string{optVal})
		if IsContextBlackListed("X-Channel-Request-Id") {
			t.Errorf("expected 'X-Channel-Request-Id' to be unblocked when optional value is %q (case-insensitive match)", optVal)
		}
	}
}

func TestOptionalHeaders_UnknownHeader_DoesNotUnblock(t *testing.T) {
	resetSingleton([]string{"X-Some-Other-Header"})

	if !IsContextBlackListed("X-Channel-Request-Id") {
		t.Error("expected 'X-Channel-Request-Id' to remain blocked when an unrelated optional header is set")
	}
}

func TestIsBlackListed_NotInDefaultList(t *testing.T) {
	resetSingleton(nil)

	if IsContextBlackListed("X-Request-Id") {
		t.Error("expected 'X-Request-Id' not to be blocked (not in default blocked list)")
	}
	if IsContextBlackListed("") {
		t.Error("expected empty string not to be blocked")
	}
}
