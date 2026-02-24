package cloudprovidergetter

import (
	"context"

	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

type CloudProvider string

const (
	// CloudProviderGKE Google Kubernetes Engine
	CloudProviderGKE = "GKE"
	// CloudProviderEKS Elastic Kubernetes Service (AWS)
	CloudProviderEKS = "EKS"
	// CloudProviderAKS Azure Kubernetes Service
	CloudProviderAKS    = "AKS"
	CloudProviderOnPrem = "OnPrem"
)

func init() {
	serviceloader.Register(0, &DefaultCloudProviderFileReader{})
}

type CloudProviderGetter interface {
	GetCloudProvider(ctx context.Context) CloudProvider
}

func GetCloudProvider(ctx context.Context) CloudProvider {
	return serviceloader.MustLoad[CloudProviderGetter]().GetCloudProvider(ctx)
}
