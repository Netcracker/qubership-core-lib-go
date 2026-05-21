package ctxmanager

import (
	"slices"
	"strings"
	"sync"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
)

var defaultBlockedHeaders = []string{"X-Channel-Request-Id"}

var (
	globalBlackLister *contextBlackLister
	once              sync.Once
)

func IsContextBlackListed(name string) bool {
	return getBlackLister().isBlackListed(name)
}

func getBlackLister() *contextBlackLister {
	once.Do(func() {
		raw := configloader.GetOrDefaultString("context.propagation.headers.enable.optional", "")
		var enabled []string
		for _, entry := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(entry); trimmed != "" {
				enabled = append(enabled, trimmed)
			}
		}
		globalBlackLister = newBlackLister(enabled)
	})

	return globalBlackLister
}

// newBlackLister builds the effective blocked-headers list by starting from
// defaultBlockedHeaders and removing any headers listed in optionallyEnabled.
func newBlackLister(optionallyEnabled []string) *contextBlackLister {
	var effectiveBlocked []string
	for _, blocked := range defaultBlockedHeaders {
		if !slices.ContainsFunc(optionallyEnabled, func(s string) bool { return strings.EqualFold(s, blocked) }) {
			effectiveBlocked = append(effectiveBlocked, blocked)
		}
	}

	return &contextBlackLister{blackListedContexts: effectiveBlocked}
}

type contextBlackLister struct {
	blackListedContexts []string
}

func (cbl *contextBlackLister) isBlackListed(contextName string) bool {
	return slices.ContainsFunc(cbl.blackListedContexts, func(s string) bool { return strings.EqualFold(s, contextName) })
}
