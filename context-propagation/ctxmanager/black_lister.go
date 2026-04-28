package ctxmanager

import (
	"os"
	"strings"
	"sync"
)

const defaultInBlackList = "X-Channel-Request-Id"

var (
	globalBlackLister *contextBlackLister
	once              sync.Once
)

func init() {
	once.Do(func() {
		raw, present := os.LookupEnv("CONTEXT_BLACK_LIST")
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

func IsContextBlackListed(name string) bool {
	return globalBlackLister.IsBlackListed(name)
}

type contextBlackLister struct {
	blackListedContexts []string
}

func (cbl *contextBlackLister) IsBlackListed(contextName string) bool {
	for _, blackListedContext := range cbl.blackListedContexts {
		if strings.EqualFold(blackListedContext, contextName) {
			return true
		}
	}
	return false
}
