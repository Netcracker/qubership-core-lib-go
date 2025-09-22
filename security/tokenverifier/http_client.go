package tokenverifier

import (
	"fmt"
	"net/http"
	"time"
)

func newSecureHttpClient(getToken getTokenFunc) (*http.Client, error) {
	base := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Transport: newSecureTransport(base, getToken)}, nil
}

type secureTransport struct {
	base http.RoundTripper
	getToken   getTokenFunc
}

func newSecureTransport(base http.RoundTripper, getToken getTokenFunc) *secureTransport {
	return &secureTransport{
		base: base,
		getToken: getToken,
	}
}

func (s *secureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := s.getToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get k8s sa token: %w", err)
	}
	r.Header.Add("Authorization", "Bearer "+token)
	return s.base.RoundTrip(r)
}
