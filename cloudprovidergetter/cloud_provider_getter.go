package cloudprovidergetter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const (
	topologyFileName = "data"
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

func (r DefaultCloudProviderFileReader) GetCloudProvider(_ context.Context) CloudProvider {
	fileName := filepath.Join(DefaultTopologyDir, topologyFileName)
	bytes, err := os.ReadFile(fileName)
	structure := &Structure{}
	if err == nil {
		err = json.Unmarshal(bytes, structure)
		if err == nil {
			return stringToCloudProvider(structure.CloudProvider)
		}
	}
	return CloudProviderOnPrem
}

func stringToCloudProvider(str string) CloudProvider {
	if cloudProvider, ok := cloudProviderByString[strings.ToLower(str)]; ok {
		return cloudProvider
	}
	return CloudProviderOnPrem
}
