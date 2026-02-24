package cloudprovidersource

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultCompositeStructurePath = "/etc/composite-structure"
	compositeStructureFileName    = "data"
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
	fileName := filepath.Join(defaultCompositeStructurePath, compositeStructureFileName)
	bytes, err := os.ReadFile(fileName)
	structure := &Structure{}
	if err == nil {
		err = json.Unmarshal(bytes, structure)
		if err == nil {
			return stringToCloudProvider(structure.CloudProvider)
		}
	}
	return CloudProviderUnknown
}

func stringToCloudProvider(str string) CloudProvider {
	if cloudProvider, ok := cloudProviderByString[strings.ToLower(str)]; ok {
		return cloudProvider
	}
	return CloudProviderUnknown
}
