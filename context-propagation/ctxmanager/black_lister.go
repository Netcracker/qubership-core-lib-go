package ctxmanager

import (
	"strings"
	"sync"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
)

const defaultInBlackList = "X-Channel-Request-Id"

var (
	globalBlackLister *contextBlackLister
	once              sync.Once
)

func IsContextBlackListed(name string) bool {
	return getBlackLister().isBlackListed(name)
}

func getBlackLister() *contextBlackLister {
	once.Do(func() {
		raw := configloader.GetOrDefault("context.black.list", defaultInBlackList) // we don't use GetOrDefaultString because we should handle empty string value
		var entries []string
		for _, entry := range strings.Split(raw.(string), ",") {
			if trimmed := strings.TrimSpace(entry); trimmed != "" {
				entries = append(entries, trimmed)
			}
		}

		globalBlackLister = &contextBlackLister{
			blackListedContexts: entries,
		}
	})

	return globalBlackLister
}

type contextBlackLister struct {
	blackListedContexts []string
}

func (cbl *contextBlackLister) isBlackListed(contextName string) bool {
	for _, blackListedContext := range cbl.blackListedContexts {
		if strings.EqualFold(blackListedContext, contextName) {
			return true
		}
	}
	return false
}
