package tokensource

import (
	"context"
	"sync"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
)

// selectableTokenSource picks a TokenSource once, like Java SelectableTokenSource:
// kubeconfig TokenRequest when SECURITY_LOCALDEV=true, otherwise projected-volume files.
// Selection is deferred to first use (Go package init runs earlier than Java ServiceLoader).
type selectableTokenSource struct {
	once     sync.Once
	delegate TokenSource
}

func newSelectableTokenSource() *selectableTokenSource {
	source := &selectableTokenSource{}
	source.ensureDelegate()
	return source
}

func (s *selectableTokenSource) ensureDelegate() {
	s.once.Do(func() {
		if localdev.IsEnabled() {
			logger.Infof("local-dev enabled: using kubeconfig TokenRequest token source")
			s.delegate = newLocalDevTokenSource()
			return
		}
		s.delegate = &DefaultTokenFileProvider{}
	})
}

func (s *selectableTokenSource) GetAudienceToken(ctx context.Context, audience TokenAudience) (string, error) {
	s.ensureDelegate()
	return s.delegate.GetAudienceToken(ctx, audience)
}

func (s *selectableTokenSource) GetServiceAccountToken(ctx context.Context) (string, error) {
	s.ensureDelegate()
	return s.delegate.GetServiceAccountToken(ctx)
}
