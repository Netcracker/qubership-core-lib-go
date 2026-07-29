package localdev

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"
)

func newHTTPClient(credentials *KubeConfigCredentials) *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig(credentials),
	}
	return &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: transport,
	}
}

func newInsecureIdpHTTPClient() *http.Client {
	transport := &http.Transport{
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local-dev IdP only
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   httpRequestTimeout,
		Transport: transport,
	}
}

func tlsConfig(credentials *KubeConfigCredentials) *tls.Config {
	if credentials == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if credentials.InsecureSkipTLSVerify {
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // kubeconfig insecure-skip-tls-verify
			MinVersion:         tls.VersionTLS12,
		}
	}
	if len(credentials.CertificateAuthorityData) == 0 {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	pool, err := certPoolFromBytes(credentials.CertificateAuthorityData)
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
}

func certPoolFromBytes(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := data
	added := false
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block != nil {
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, err
				}
				pool.AddCert(cert)
				added = true
			}
			rest = remaining
			continue
		}
		cert, err := x509.ParseCertificate(rest)
		if err != nil {
			if !added {
				return nil, fmt.Errorf("failed to parse kubeconfig CA: %w", err)
			}
			break
		}
		pool.AddCert(cert)
		added = true
		break
	}
	if !added {
		return nil, fmt.Errorf("no certificates found in kubeconfig certificate-authority-data")
	}
	return pool, nil
}
