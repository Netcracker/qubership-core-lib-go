package tokenverifier

import (
	"net/http"
	"time"

	"github.com/failsafe-go/failsafe-go/failsafehttp"
)

const (
	retryMaxAttempts     = 5
	retryBackoffDelay    = time.Millisecond * 500
	retryBackoffMaxDelay = time.Second * 15
	retryJitter          = time.Millisecond * 100
)

func CreateHttpClient(innerRoundTripper http.RoundTripper) http.Client {
	return http.Client{
		Transport: failsafehttp.NewRoundTripper(
			innerRoundTripper,
			failsafehttp.NewRetryPolicyBuilder().
				WithMaxAttempts(retryMaxAttempts).
				WithBackoff(retryBackoffDelay, retryBackoffMaxDelay).
				WithJitter(retryJitter).
				Build(),
		),
	}
}
