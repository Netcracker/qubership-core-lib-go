package cloudprovidergetter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetect_ReturnsGKE_WhenMetadataFlavorIsGoogle(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Metadata-Flavor", "Google")
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/latest/meta-data/", notFoundHandler)
		mux.HandleFunc("/metadata/instance", notFoundHandler)
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderGKE), detect(context.Background(), server.URL))
}

func TestDetect_NotGKE_WhenMetadataFlavorHeaderAbsent(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/latest/meta-data/", notFoundHandler)
		mux.HandleFunc("/metadata/instance", notFoundHandler)
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderOnPrem), detect(context.Background(), server.URL))
}

func TestDetect_ReturnsEKS_WhenImdsV1Returns200(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", notFoundHandler)
		mux.HandleFunc("/latest/meta-data/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/metadata/instance", notFoundHandler)
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderEKS), detect(context.Background(), server.URL))
}

func TestDetect_ReturnsEKS_WhenImdsV2Returns401(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", notFoundHandler)
		mux.HandleFunc("/latest/meta-data/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		mux.HandleFunc("/metadata/instance", notFoundHandler)
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderEKS), detect(context.Background(), server.URL))
}

func TestDetect_NotEKS_WhenImdsReturns403(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", notFoundHandler)
		mux.HandleFunc("/latest/meta-data/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		mux.HandleFunc("/metadata/instance", notFoundHandler)
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderOnPrem), detect(context.Background(), server.URL))
}

func TestDetect_ReturnsAKS_WhenAzureInstanceEndpointReturns200(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", notFoundHandler)
		mux.HandleFunc("/latest/meta-data/", notFoundHandler)
		mux.HandleFunc("/metadata/instance", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`))
		})
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderAKS), detect(context.Background(), server.URL))
}

func TestDetect_NotAKS_WhenAzureEndpointReturns404(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", notFoundHandler)
		mux.HandleFunc("/latest/meta-data/", notFoundHandler)
		mux.HandleFunc("/metadata/instance", notFoundHandler)
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderOnPrem), detect(context.Background(), server.URL))
}

func TestDetect_ReturnsOnPrem_WhenMetadataUnreachable(t *testing.T) {
	assert.Equal(t, CloudProvider(CloudProviderOnPrem), detect(context.Background(), "http://127.0.0.1:1"))
}

func TestDetect_ReturnsOnPrem_WhenAllEndpointsReturn500(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", statusHandler(http.StatusInternalServerError))
		mux.HandleFunc("/latest/meta-data/", statusHandler(http.StatusInternalServerError))
		mux.HandleFunc("/metadata/instance", statusHandler(http.StatusInternalServerError))
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderOnPrem), detect(context.Background(), server.URL))
}

func TestDetect_PrefersGKE_WhenBothGKEAndEKSProbesSucceed(t *testing.T) {
	server := newMetadataServer(t, func(mux *http.ServeMux) {
		mux.HandleFunc("/computeMetadata/v1/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Metadata-Flavor", "Google")
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/latest/meta-data/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/metadata/instance", notFoundHandler)
	})
	defer server.Close()

	assert.Equal(t, CloudProvider(CloudProviderGKE), detect(context.Background(), server.URL))
}

func TestGetCloudProvider_IsUncomputed_BeforeFirstDetection(t *testing.T) {
	reader := &DefaultCloudProviderFileReader{}
	assert.Equal(t, CloudProvider(""), reader.detected)
}

func TestGetCloudProvider_ReturnsAndKeepsCachedValue_OnceDetected(t *testing.T) {
	reader := &DefaultCloudProviderFileReader{}

	// Manually prime the cache for the test case
	reader.detected = CloudProvider(CloudProviderAKS)
	reader.detectOnce.Do(func() {}) // Lock the sync.Once

	assert.Equal(t, CloudProvider(CloudProviderAKS), reader.GetCloudProvider(context.Background()))
	assert.Equal(t, CloudProvider(CloudProviderAKS), reader.GetCloudProvider(context.Background()))
}

func newMetadataServer(t *testing.T, register func(mux *http.ServeMux)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	register(mux)
	return httptest.NewServer(mux)
}

func notFoundHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func statusHandler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}
}
