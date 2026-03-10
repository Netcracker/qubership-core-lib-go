package tokenverifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/cloudprovidergetter"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"golang.org/x/time/rate"
)

const (
	oidcError        = "unexpected issue during oidc call to '%s', cloud provider '%s': %s"
	oidcErrorReasons = "possible reasons are:\n" +
		"1. outdated base image without kubernetes service account ca.crt -> please check your base image version\n" +
		"2. lack of access to the Kubernetes API for the EKS cloud provider -> please check firewall setting (pod -> kubernetes api access is required!)"
)

type KeyFuncOptions struct {
	HttpClient        *http.Client
	TrustedIssuer     string
	RefreshInterval   time.Duration
	RefreshUnknownKID *rate.Limiter
}

func CreateKeyFunction(ctx context.Context, options KeyFuncOptions) (keyfunc.Keyfunc, error) {
	issuerUrl, err := oidc.GetProviderUrl(options.TrustedIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer url: %w", err)
	}
	request, err := http.NewRequest(http.MethodGet, issuerUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc request: %w", err)
	}
	provider := cloudprovidergetter.GetCloudProvider(ctx)
	response, err := options.HttpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf(oidcError+": %w", issuerUrl, provider, oidcErrorReasons, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf(oidcError+": %w", issuerUrl, provider, "unable to read oidc response body, "+oidcErrorReasons, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(oidcError, issuerUrl, provider, fmt.Sprintf("unexpected response http status code %s, %s", response.Status, oidcErrorReasons))
	}
	var providerResponse oidc.ProviderResponse
	err = unmarshalResponse(response, body, &providerResponse)
	if err != nil {
		return nil, fmt.Errorf(oidcError+": %w", issuerUrl, provider, "failed to decode provider discovery object, "+oidcErrorReasons, err)
	}
	return keyfunc.NewDefaultOverrideCtx(
		ctx,
		[]string{providerResponse.JwksUri},
		keyfunc.Override{Client: options.HttpClient, RefreshInterval: options.RefreshInterval, RefreshUnknownKID: options.RefreshUnknownKID},
	)
}
func unmarshalResponse(response *http.Response, body []byte, result interface{}) error {
	err := json.Unmarshal(body, &result)
	if err == nil {
		return nil
	}
	contentType := response.Header.Get("Content-Type")
	mediaType, _, cerr := mime.ParseMediaType(contentType)
	if cerr == nil && mediaType == "application/json" {
		return fmt.Errorf("got content-type = application/json, but could not unmarshal as json: %w", err)
	}
	return fmt.Errorf("expected content-type = application/json, got %q: %w", contentType, err)
}
