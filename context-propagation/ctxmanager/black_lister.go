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
		globalBlackLister = &contextBlackLister{}

		loadEntries := func() []string {
			raw := configloader.GetOrDefault("headers.blocked", defaultInBlackList)
			str, ok := raw.(string)
			if !ok {
				logger.Error("unexpected type for headers.blocked: %T", raw)
				return nil
			}
			var entries []string
			for _, entry := range strings.Split(str, ",") {
				if trimmed := strings.TrimSpace(entry); trimmed != "" {
					entries = append(entries, trimmed)
				}
			}
			return entries
		}

		globalBlackLister.blackListedContexts = loadEntries() // initial load before Subscribe

		_, err := configloader.Subscribe(func(event configloader.Event) error {
			entries := loadEntries()
			globalBlackLister.mu.Lock()
			globalBlackLister.blackListedContexts = entries
			globalBlackLister.mu.Unlock()
			return nil
		})
		if err != nil {
			logger.Error("error subscribing to black lister: %v", err)
		}
	})

	return globalBlackLister
}

type contextBlackLister struct {
	blackListedContexts []string
	mu                  sync.RWMutex
}

func (cbl *contextBlackLister) isBlackListed(contextName string) bool {
	cbl.mu.RLock()
	defer cbl.mu.RUnlock()
	for _, blackListedContext := range cbl.blackListedContexts {
		if strings.EqualFold(blackListedContext, contextName) {
			return true
		}
	}
	return false
}
