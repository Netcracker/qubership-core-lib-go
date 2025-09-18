package tokenverifier

import (
	"fmt"
	"net/http"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
)

func newSecureHttpClient(tokenSource tokensource.TokenSource) (*http.Client, error) {
	base := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Transport: newSecureTransport(base, tokenSource)}, nil
}

type secureTransport struct {
	base http.RoundTripper
	ts   tokensource.TokenSource
}

func newSecureTransport(base http.RoundTripper, ts tokensource.TokenSource) *secureTransport {
	return &secureTransport{
		base: base,
		ts:   ts,
	}
}

func (s *secureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := s.ts.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get k8s sa token: %w", err)
	}
	r.Header.Add("Authorization", "Bearer "+token)
	return s.base.RoundTrip(r)
}
