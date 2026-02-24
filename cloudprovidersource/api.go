package cloudprovidersource

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
	CloudProviderUnknown = "Unknown"
)

func init() {
	serviceloader.Register(0, &DefaultCloudProviderFileReader{})
}

type CloudProviderSource interface {
	GetCloudProvider(ctx context.Context) CloudProvider
}

func GetCloudProvider(ctx context.Context) CloudProvider {
	return serviceloader.MustLoad[CloudProviderSource]().GetCloudProvider(ctx)
}
