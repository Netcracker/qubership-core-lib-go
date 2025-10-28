package token

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// see https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
const (
	KubernetesIo            = "kubernetes.io"
	Namespace               = "namespace"
	Node                    = "node"
	Pod                     = "pod"
	ServiceAccount          = "serviceaccount"
	Name                    = "name"
	Uid                     = "uid"
	Warnafter               = "warnafter"
	ServiceAccountSubPrefix = "system:serviceaccount"
)

type KubernetesClaims struct {
	jwt.RegisteredClaims
	KubernetesIo KubernetesIoClaim `json:"kubernetes.io"`
}

type KubernetesIoClaim struct {
	Namespace      string              `json:"namespace,omitempty"`
	ServiceAccount ServiceAccountClaim `json:"serviceaccount"`
	Node           NodeClaim           `json:"node"`
	Pod            PodClaim            `json:"pod"`
	WarnAfter      *jwt.NumericDate    `json:"warnafter,omitempty"`
}

type ServiceAccountClaim struct {
	Name string `json:"name,omitempty"`
	Uid  string `json:"uid,omitempty"`
}

type NodeClaim struct {
	Name string `json:"name,omitempty"`
	Uid  string `json:"uid,omitempty"`
}

type PodClaim struct {
	Name string `json:"name,omitempty"`
	Uid  string `json:"uid,omitempty"`
}

func GetKubernetesSubject(namespace, serviceAccount string) string {
	return fmt.Sprintf("%s:%s:%s", ServiceAccountSubPrefix, namespace, serviceAccount)
}
func IsKubernetesToken(token *jwt.Token) bool {
	_, err := GetMapValue(token, KubernetesIo)
	if err == nil {
		return true
	} else {
		return false
	}
}
func GetKubernetesIo(token *jwt.Token) (KubernetesIoClaim, error) {
	kubernetesIoMap, err := GetMapValue(token, KubernetesIo)
	empty := KubernetesIoClaim{}
	if err != nil {
		return empty, err
	}
	serviceAccount, _ := getServiceAccount(kubernetesIoMap)
	node, _ := getNode(kubernetesIoMap)
	pod, _ := getPod(kubernetesIoMap)
	namespace, _ := getStringValue(kubernetesIoMap, Namespace)
	warnAfter, _ := getNumericDateValue(kubernetesIoMap, Warnafter)
	return KubernetesIoClaim{
		ServiceAccount: serviceAccount,
		Node:           node,
		Pod:            pod,
		Namespace:      namespace,
		WarnAfter:      warnAfter,
	}, nil
}
func GetServiceAccount(token *jwt.Token) (ServiceAccountClaim, error) {
	kubernetesIoMap, err := GetMapValue(token, KubernetesIo)
	if err != nil {
		return ServiceAccountClaim{}, err
	}
	return getServiceAccount(kubernetesIoMap)
}
func GetNode(token *jwt.Token) (NodeClaim, error) {
	kubernetesIoMap, err := GetMapValue(token, KubernetesIo)
	if err != nil {
		return NodeClaim{}, err
	}
	return getNode(kubernetesIoMap)
}
func GetPod(token *jwt.Token) (PodClaim, error) {
	kubernetesIoMap, err := GetMapValue(token, KubernetesIo)
	if err != nil {
		return PodClaim{}, err
	}
	return getPod(kubernetesIoMap)
}
func GetNamespace(token *jwt.Token) (string, error) {
	kubernetesIoMap, err := GetMapValue(token, KubernetesIo)
	if err != nil {
		return "", err
	}
	return getStringValue(kubernetesIoMap, Namespace)
}
func getServiceAccount(kubernetesIoMap jwt.MapClaims) (ServiceAccountClaim, error) {
	serviceAccountId, serviceAccountName, err := getEntity(kubernetesIoMap, ServiceAccount)
	if err != nil {
		return ServiceAccountClaim{
			Name: serviceAccountName,
			Uid:  serviceAccountId,
		}, err
	}
	return ServiceAccountClaim{
		Name: serviceAccountName,
		Uid:  serviceAccountId}, nil
}
func getNode(kubernetesIoMap jwt.MapClaims) (NodeClaim, error) {
	nodeId, nodeName, err := getEntity(kubernetesIoMap, Node)
	if err != nil {
		return NodeClaim{
			Name: nodeName,
			Uid:  nodeId,
		}, err
	}
	return NodeClaim{
		Name: nodeName,
		Uid:  nodeId}, nil
}
func getPod(kubernetesIoMap jwt.MapClaims) (PodClaim, error) {
	podId, podName, err := getEntity(kubernetesIoMap, Pod)
	if err != nil {
		return PodClaim{
			Name: podName,
			Uid:  podId,
		}, err
	}
	return PodClaim{
		Name: podName,
		Uid:  podId}, nil
}
func getEntity(claims jwt.MapClaims, claimName string) (string, string, error) {
	claimMap, err := getMapValue(claims, claimName)
	if err != nil {
		return "", "", err
	}
	entityName, _ := getStringValue(claimMap, Name)
	entityId, _ := getStringValue(claimMap, Uid)
	return entityId, entityName, nil
}
