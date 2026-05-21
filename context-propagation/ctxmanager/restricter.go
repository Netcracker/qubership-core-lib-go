package ctxmanager

import (
	"slices"
	"strings"
	"sync"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
)

const optionalHeadersEnabledConfigKey = "context.propagation.headers.enable.optional"

var defaultRestrictedHeaders = []string{"X-Channel-Request-Id"}

var (
	globalContextRestricter *contextRestricter
	once                    sync.Once
)

func IsContextRestricted(name string) bool {
	return getContextRestricter().isRestricted(name)
}

func getContextRestricter() *contextRestricter {
	once.Do(func() {
		raw := configloader.GetOrDefaultString(optionalHeadersEnabledConfigKey, "")
		var enabled []string
		for _, entry := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(entry); trimmed != "" {
				enabled = append(enabled, trimmed)
			}
		}
		globalContextRestricter = newContextRestricter(enabled)
	})

	return globalContextRestricter
}

// newContextRestricter builds the effective restricted-headers list by starting from
// defaultRestrictedHeaders and removing any headers listed in optionallyEnabled.
func newContextRestricter(optionallyEnabled []string) *contextRestricter {
	var effectiveBlocked []string
	for _, restricted := range defaultRestrictedHeaders {
		if !slices.ContainsFunc(optionallyEnabled, func(s string) bool { return strings.EqualFold(s, restricted) }) {
			effectiveBlocked = append(effectiveBlocked, restricted)
		}
	}

	return &contextRestricter{restrictedContexts: effectiveBlocked}
}

type contextRestricter struct {
	restrictedContexts []string
}

func (cbl *contextRestricter) isRestricted(contextName string) bool {
	return slices.ContainsFunc(cbl.restrictedContexts, func(s string) bool { return strings.EqualFold(s, contextName) })
}
