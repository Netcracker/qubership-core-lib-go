package cloudprovidergetter

import (
	"context"
	"net/http"
	"sync"
	"time"
)

var (
	// DefaultTopologyDir is the default directory where topology config map is mounted
	DefaultTopologyDir = "/etc/topology"
)

var cloudProviderByString = map[string]CloudProvider{
	"eks":    CloudProviderEKS,
	"gke":    CloudProviderGKE,
	"aks":    CloudProviderAKS,
	"onprem": CloudProviderOnPrem,
}

type DefaultCloudProviderFileReader struct {
}

type Structure struct {
	CloudProvider string `json:"cloudProvider"`
}

const (
	defaultMetadataURL = "http://169.254.169.254"
)

var (
	detected   CloudProvider
	detectedMu sync.Mutex
)

func (r DefaultCloudProviderFileReader) GetCloudProvider(ctx context.Context) CloudProvider {
	detectedMu.Lock()
	defer detectedMu.Unlock()
	if detected == "" {
		detected = detect(ctx, defaultMetadataURL)
	}
	return detected
}

func detect(ctx context.Context, metadataURL string) CloudProvider {
	if isGke(ctx, metadataURL) {
		return CloudProviderGKE
	}
	if isEks(ctx, metadataURL) {
		return CloudProviderEKS
	}
	if isAks(ctx, metadataURL) {
		return CloudProviderAKS
	}
	return CloudProviderOnPrem
}

func isGke(ctx context.Context, metadataURL string) bool {
	resp, err := probe(ctx, metadataURL+"/computeMetadata/v1/", map[string]string{
		"Metadata-Flavor": "Google",
	})
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && resp.Header.Get("Metadata-Flavor") == "Google"
}

func isEks(ctx context.Context, metadataURL string) bool {
	resp, err := probe(ctx, metadataURL+"/latest/meta-data/", nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized
}

func isAks(ctx context.Context, metadataURL string) bool {
	resp, err := probe(ctx, metadataURL+"/metadata/instance?api-version=2021-02-01", map[string]string{
		"Metadata": "true",
	})
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func probe(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return http.DefaultClient.Do(req)
}
