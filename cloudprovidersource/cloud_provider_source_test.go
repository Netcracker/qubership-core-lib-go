package cloudprovidersource

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringToCloudProvider_KnownAndCaseInsensitive(t *testing.T) {
	testCases := []struct {
		str      string
		expected string
	}{
		{"eks", CloudProviderEKS},
		{"EKS", CloudProviderEKS},
		{"gke", CloudProviderGKE},
		{"GkE", CloudProviderGKE},
		{"aks", CloudProviderAKS},
		{"AKS", CloudProviderAKS},
		{"onprem", CloudProviderOnPrem},
		{"OnPrEm", CloudProviderOnPrem},
	}

	for _, testCase := range testCases {
		actual := stringToCloudProvider(testCase.str)
		assert.Equal(t, testCase.expected, string(actual))
	}
}

func TestStringToCloudProvider_Unknown(t *testing.T) {
	testCases := []string{"", "unknown", "something", "eks ", " gke"}
	for _, str := range testCases {
		actual := stringToCloudProvider(str)
		assert.Equal(t, CloudProviderUnknown, string(actual))
	}
}

func TestDefaultCloudProviderFileReader_GetCloudProvider_FileMissing(t *testing.T) {
	withCompositeStructureFileState(t, nil, func() {
		cloudProvider := GetCloudProvider(t.Context())
		assert.Equal(t, CloudProviderUnknown, string(cloudProvider))
	})
}

func TestDefaultCloudProviderFileReader_GetCloudProvider_InvalidJSON(t *testing.T) {
	withCompositeStructureFileState(t, []byte(`{"cloudProvider":`), func() {
		cloudProvider := GetCloudProvider(t.Context())
		assert.Equal(t, CloudProviderUnknown, string(cloudProvider))
	})
}

func TestDefaultCloudProviderFileReader_GetCloudProvider_ValidJSONKnownProvider(t *testing.T) {
	withCompositeStructureFileState(t, []byte(`{"cloudProvider":"EKS"}`), func() {
		cloudProvider := GetCloudProvider(t.Context())
		assert.Equal(t, CloudProviderEKS, string(cloudProvider))
	})
}

func TestDefaultCloudProviderFileReader_GetCloudProvider_ValidJSONUnknownProvider(t *testing.T) {
	withCompositeStructureFileState(t, []byte(`{"cloudProvider":"some-new-cloud"}`), func() {
		cloudProvider := GetCloudProvider(t.Context())
		assert.Equal(t, CloudProviderUnknown, string(cloudProvider))
	})
}

func withCompositeStructureFileState(t *testing.T, content []byte, test func()) {
	t.Helper()

	dir := defaultCompositeStructurePath
	file := filepath.Join(defaultCompositeStructurePath, compositeStructureFileName)

	err := os.MkdirAll(dir, 0775)
	assert.NoError(t, err)
	if content != nil {
		err = os.WriteFile(file, content, 0644)
		assert.NoError(t, err)
	}

	test()

	_ = os.Remove(file)
	_ = os.Remove(dir)
}
