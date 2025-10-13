# Token Verifier

A Go package for verifying Kubernetes service account tokens using OIDC (OpenID Connect) token verification with built-in retry and failsafe mechanisms.

## Table of Contents

* [Overview](#overview)
* [Installation](#installation)
* [Features](#features)
* [Quick Start](#quick-start)
* [Usage](#usage)
    * [Basic Verification](#basic-verification)
    * [Understanding Claims](#understanding-claims)
    * [Error Handling](#error-handling)
* [Configuration](#configuration)
* [Architecture](#architecture)
    * [Retry Policy](#retry-policy)
    * [Security](#security)
* [API Reference](#api-reference)
    * [Types](#types)
    * [Functions](#functions)
* [Examples](#examples)
* [Best Practices](#best-practices)
* [Troubleshooting](#troubleshooting)

## Overview

The `tokenverifier` package provides a secure, production-ready solution for verifying Kubernetes service account tokens using OIDC standards. It automatically handles:

- OIDC provider discovery and configuration
- Token verification with audience validation
- Automatic retries with exponential backoff
- Secure HTTP transport for OIDC operations
- Kubernetes-specific claims extraction

## Installation

```bash
go get github.com/netcracker/qubership-core-lib-go/v3
```

## Features

✅ **OIDC-based Verification** - Standards-compliant token verification  
✅ **Automatic Retries** - Built-in failsafe mechanism with exponential backoff  
✅ **Kubernetes Integration** - Native support for K8s service account tokens  
✅ **Secure by Default** - Uses secure transport with proper token authentication  
✅ **Flexible Configuration** - Customizable audience validation  
✅ **Rich Claims Extraction** - Access to both standard JWT and Kubernetes-specific claims

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    "github.com/netcracker/qubership-core-lib-go/v3/security/tokenverifier"
)

func main() {
    ctx := context.Background()
    
    // Create a verifier with your service's audience
    verifier, err := tokenverifier.New(ctx, "my-service-audience")
    if err != nil {
        log.Fatalf("Failed to create verifier: %v", err)
    }
    
    // Verify a token
    token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." // Raw JWT token
    claims, err := verifier.Verify(ctx, token)
    if err != nil {
        log.Fatalf("Token verification failed: %v", err)
    }
    
    log.Printf("Token verified for service account: %s in namespace: %s", 
        claims.Kubernetes.ServiceAccount.Name,
        claims.Kubernetes.Namespace)
}
```

## Usage

### Basic Verification

#### Step 1: Create a Verifier

```go
import (
    "context"
    "github.com/netcracker/qubership-core-lib-go/v3/security/tokenverifier"
)

ctx := context.Background()
audience := "my-service" // Your service identifier

verifier, err := tokenverifier.New(ctx, audience)
if err != nil {
    // Handle error - typically indicates:
    // - Projected volume token not configured
    // - OIDC provider unreachable
    // - Invalid token format
    return err
}
```

#### Step 2: Verify Tokens

```go
// Verify an incoming token (e.g., from HTTP Authorization header)
rawToken := extractTokenFromRequest(r) // Your token extraction logic

claims, err := verifier.Verify(ctx, rawToken)
if err != nil {
    // Token is invalid or expired
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}

// Token is valid - use claims
log.Printf("Authenticated: %s", claims.Subject)
```

### Understanding Claims

The `Claims` struct contains both standard JWT claims and Kubernetes-specific information:

```go
type Claims struct {
    jwt.RegisteredClaims // Standard JWT claims
    Kubernetes K8sClaims `json:"kubernetes.io"`
}

type K8sClaims struct {
    Namespace      string         `json:"namespace,omitempty"`
    ServiceAccount ServiceAccount `json:"serviceaccount"`
}

type ServiceAccount struct {
    Name string `json:"name,omitempty"`
    Uid  string `json:"uid,omitempty"`
}
```

#### Accessing Standard JWT Claims

```go
claims, _ := verifier.Verify(ctx, token)

// Standard JWT claims (from jwt.RegisteredClaims)
issuer := claims.Issuer           // Token issuer
subject := claims.Subject          // Token subject
audience := claims.Audience        // Intended audience
expiresAt := claims.ExpiresAt      // Expiration time
notBefore := claims.NotBefore      // Not valid before time
issuedAt := claims.IssuedAt        // Issued at time
jwtID := claims.ID                 // JWT ID
```

#### Accessing Kubernetes Claims

```go
claims, _ := verifier.Verify(ctx, token)

// Kubernetes-specific claims
namespace := claims.Kubernetes.Namespace
serviceAccountName := claims.Kubernetes.ServiceAccount.Name
serviceAccountUID := claims.Kubernetes.ServiceAccount.Uid

log.Printf("Service account %s/%s (UID: %s)", 
    namespace, 
    serviceAccountName, 
    serviceAccountUID)
```

### Error Handling

```go
claims, err := verifier.Verify(ctx, token)
if err != nil {
    // Common error scenarios:
    // - Token expired
    // - Invalid signature
    // - Wrong audience
    // - Malformed token
    // - Claims missing
    
    log.Printf("Verification failed: %v", err)
    
    // Return appropriate HTTP status
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}
```

## Configuration

### Default Retry Configuration

The verifier uses the following retry policy for OIDC operations:

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Max Attempts** | 5 | Maximum number of retry attempts |
| **Initial Delay** | 500ms | Starting backoff delay |
| **Max Delay** | 15s | Maximum backoff delay |
| **Jitter** | 100ms | Random jitter added to delays |

These values are optimized for production use and handle transient network issues automatically.

### Kubernetes Prerequisites

The verifier requires a Kubernetes projected service account token volume. Ensure your deployment has the following configuration:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-service
spec:
  serviceAccountName: my-service-account
  containers:
  - name: app
    image: my-image
    volumeMounts:
    - name: token
      mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      readOnly: true
  volumes:
  - name: token
    projected:
      sources:
      - serviceAccountToken:
          audience: my-service  # Must match verifier audience
          expirationSeconds: 3600
          path: token
```

## Architecture

### Retry Policy

The verifier implements intelligent retry logic:

```go
// Retries are attempted for:
✅ Non-URL errors (network issues, timeouts)
✅ 5xx server errors from OIDC provider

// No retries for:
❌ URL errors (malformed URLs)
❌ 2xx, 3xx, 4xx responses
```

**Backoff Strategy:**
- Exponential backoff starting at 500ms
- Capped at 15 seconds maximum
- Random jitter of ±100ms to prevent thundering herd

### Security

#### Secure Transport

The verifier uses a secure HTTP transport that:
- Automatically attaches service account tokens to OIDC requests
- Uses the Kubernetes projected token for authentication
- Implements proper TLS verification

#### Token Verification Process

1. **Extract Issuer** - Parse the token to identify the OIDC issuer
2. **Provider Discovery** - Connect to OIDC provider using `.well-known` endpoints
3. **Fetch Public Keys** - Retrieve signing keys (JWKS) from provider
4. **Signature Verification** - Cryptographically verify token signature
5. **Claims Validation** - Verify audience, expiration, and required claims
6. **Claims Extraction** - Parse and return validated claims

## API Reference

### Types

#### Verifier Interface

```go
type Verifier interface {
    Verify(ctx context.Context, rawToken string) (*Claims, error)
}
```

Primary interface for token verification.

#### Claims

```go
type Claims struct {
    jwt.RegisteredClaims
    Kubernetes K8sClaims `json:"kubernetes.io"`
}
```

Contains all claims extracted from a verified token.

#### K8sClaims

```go
type K8sClaims struct {
    Namespace      string         `json:"namespace,omitempty"`
    ServiceAccount ServiceAccount `json:"serviceaccount"`
}
```

Kubernetes-specific claims including namespace and service account information.

#### ServiceAccount

```go
type ServiceAccount struct {
    Name string `json:"name,omitempty"`
    Uid  string `json:"uid,omitempty"`
}
```

Service account identity information.

### Functions

#### New

```go
func New(ctx context.Context, audience string) (Verifier, error)
```

Creates a new token verifier.

**Parameters:**
- `ctx` - Context for OIDC provider initialization
- `audience` - Expected audience claim value (typically your service identifier)

**Returns:**
- `Verifier` - Token verifier instance
- `error` - Error if initialization fails

**Errors:**
- Projected volume token not found or misconfigured
- Unable to parse token or extract issuer
- OIDC provider unreachable or invalid

**Example:**
```go
verifier, err := tokenverifier.New(ctx, "my-api-gateway")
if err != nil {
    log.Fatalf("Failed to initialize verifier: %v", err)
}
```

#### Verify

```go
func (vf *verifier) Verify(ctx context.Context, rawToken string) (*Claims, error)
```

Verifies a token and extracts claims.

**Parameters:**
- `ctx` - Context for verification operation
- `rawToken` - Raw JWT token string

**Returns:**
- `*Claims` - Verified token claims
- `error` - Error if verification fails

**Errors:**
- Token signature invalid
- Token expired or not yet valid
- Audience mismatch
- Required claims missing
- Malformed token

**Example:**
```go
claims, err := verifier.Verify(ctx, bearerToken)
if err != nil {
    return fmt.Errorf("invalid token: %w", err)
}
```

## Examples

### Example 1: HTTP Middleware

```go
func AuthMiddleware(verifier tokenverifier.Verifier) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract token from Authorization header
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Missing authorization", http.StatusUnauthorized)
                return
            }
            
            // Remove "Bearer " prefix
            token := strings.TrimPrefix(authHeader, "Bearer ")
            
            // Verify token
            claims, err := verifier.Verify(r.Context(), token)
            if err != nil {
                log.Printf("Token verification failed: %v", err)
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }
            
            // Add claims to context
            ctx := context.WithValue(r.Context(), "claims", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Usage
func main() {
    verifier, _ := tokenverifier.New(context.Background(), "my-service")
    
    router := http.NewServeMux()
    router.Handle("/api/", AuthMiddleware(verifier)(apiHandler))
    
    http.ListenAndServe(":8080", router)
}
```

### Example 2: gRPC Interceptor

```go
func UnaryAuthInterceptor(verifier tokenverifier.Verifier) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        // Extract token from metadata
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "missing metadata")
        }
        
        tokens := md.Get("authorization")
        if len(tokens) == 0 {
            return nil, status.Error(codes.Unauthenticated, "missing token")
        }
        
        token := strings.TrimPrefix(tokens[0], "Bearer ")
        
        // Verify token
        claims, err := verifier.Verify(ctx, token)
        if err != nil {
            return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
        }
        
        // Add claims to context
        ctx = context.WithValue(ctx, "claims", claims)
        return handler(ctx, req)
    }
}
```

### Example 3: Service-to-Service Authentication

```go
func CallDownstreamService(ctx context.Context, verifier tokenverifier.Verifier) error {
    // Get current service's token
    token, err := tokensource.GetServiceAccountToken(ctx)
    if err != nil {
        return fmt.Errorf("failed to get service token: %w", err)
    }
    
    // Create request to downstream service
    req, _ := http.NewRequestWithContext(ctx, "GET", "https://downstream-service/api", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    
    // Downstream service will verify this token using their own verifier
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    // Handle response...
    return nil
}
```

### Example 4: Authorization Based on Claims

```go
func RequireNamespace(allowedNamespaces []string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, ok := r.Context().Value("claims").(*tokenverifier.Claims)
            if !ok {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }
            
            // Check if service account is in allowed namespace
            allowed := false
            for _, ns := range allowedNamespaces {
                if claims.Kubernetes.Namespace == ns {
                    allowed = true
                    break
                }
            }
            
            if !allowed {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

// Usage
router.Handle("/admin/", 
    RequireNamespace([]string{"admin", "operators"})(adminHandler))
```

## Best Practices

### 1. Create Verifier Once

Create the verifier during application startup, not per-request:

```go
// ✅ Good - Create once
var globalVerifier tokenverifier.Verifier

func init() {
    var err error
    globalVerifier, err = tokenverifier.New(context.Background(), "my-service")
    if err != nil {
        log.Fatal(err)
    }
}

// ❌ Bad - Creating per request
func handler(w http.ResponseWriter, r *http.Request) {
    verifier, _ := tokenverifier.New(r.Context(), "my-service") // Don't do this!
}
```

### 2. Use Context Properly

Pass request context to Verify for proper timeout and cancellation handling:

```go
// ✅ Good
claims, err := verifier.Verify(r.Context(), token)

// ❌ Bad
claims, err := verifier.Verify(context.Background(), token)
```

### 3. Handle Errors Gracefully

```go
claims, err := verifier.Verify(ctx, token)
if err != nil {
    // Log the error for debugging
    log.Printf("Token verification failed: %v", err)
    
    // Return generic error to client (don't leak details)
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}
```

### 4. Validate Additional Claims

Beyond verification, validate claims match your requirements:

```go
claims, err := verifier.Verify(ctx, token)
if err != nil {
    return err
}

// Additional validation
if claims.Kubernetes.Namespace != expectedNamespace {
    return errors.New("wrong namespace")
}

if claims.Kubernetes.ServiceAccount.Name != expectedSA {
    return errors.New("wrong service account")
}
```

### 5. Set Appropriate Token Expiration

In your Kubernetes deployment, balance security and performance:

```yaml
# Short expiration for high-security scenarios
expirationSeconds: 600  # 10 minutes

# Longer expiration for performance
expirationSeconds: 3600  # 1 hour (default)
```

## Troubleshooting

### Common Issues

#### Error: "failed to get k8s projected volume token"

**Cause:** Projected service account token not configured in Kubernetes deployment.

**Solution:** Add projected token volume to your pod spec (see [Kubernetes Prerequisites](#kubernetes-prerequisites)).

#### Error: "failed to create oidc provider"

**Cause:** Unable to reach OIDC provider (typically Kubernetes API server).

**Possible causes:**
- Network connectivity issues
- Kubernetes API server unavailable
- Invalid issuer URL

**Solution:**
- Check network policies
- Verify Kubernetes API server is accessible
- Check pod logs for network errors

#### Error: "failed to verify token: audience mismatch"

**Cause:** Token audience doesn't match verifier's expected audience.

**Solution:** Ensure the `audience` parameter in `New()` matches the `audience` in your projected token volume:

```go
// Verifier
verifier, _ := tokenverifier.New(ctx, "my-service")

// Must match deployment
serviceAccountToken:
  audience: my-service  # Must be identical
```

#### Error: "token has expired"

**Cause:** Token expired or clock skew between services.

**Solution:**
- Check `expirationSeconds` in projected token config
- Ensure NTP is configured correctly on nodes
- Token is automatically refreshed - ensure your app reads fresh token

#### Slow Initial Verification

**Cause:** First verification requires OIDC provider discovery and key fetching.

**Solution:** This is expected. Subsequent verifications use cached provider configuration and are much faster. Consider warming up the verifier at startup:

```go
func warmupVerifier(verifier tokenverifier.Verifier) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Get a valid token and verify it to cache provider config
    token, _ := tokensource.GetServiceAccountToken(ctx)
    _, _ = verifier.Verify(ctx, token)
}
```

### Debug Mode

Enable detailed logging to troubleshoot issues:

```go
import "log"

claims, err := verifier.Verify(ctx, token)
if err != nil {
    log.Printf("Verification error: %v", err)
    log.Printf("Token (first 20 chars): %s...", token[:min(20, len(token))])
    // Don't log full token in production!
}
```

### Testing

For unit tests, consider using a mock verifier:

```go
type MockVerifier struct {
    VerifyFunc func(context.Context, string) (*tokenverifier.Claims, error)
}

func (m *MockVerifier) Verify(ctx context.Context, token string) (*tokenverifier.Claims, error) {
    if m.VerifyFunc != nil {
        return m.VerifyFunc(ctx, token)
    }
    return &tokenverifier.Claims{}, nil
}

// In tests
mockVerifier := &MockVerifier{
    VerifyFunc: func(ctx context.Context, token string) (*tokenverifier.Claims, error) {
        if token == "valid" {
            return &tokenverifier.Claims{
                Kubernetes: tokenverifier.K8sClaims{
                    Namespace: "test",
                },
            }, nil
        }
        return nil, errors.New("invalid token")
    },
}
```

---

## Dependencies

- `github.com/coreos/go-oidc/v3/oidc` - OIDC token verification
- `github.com/failsafe-go/failsafe-go/failsafehttp` - Retry and circuit breaker
- `github.com/golang-jwt/jwt/v5` - JWT parsing
- `github.com/netcracker/qubership-core-lib-go/v3/security/tokensource` - Service account token retrieval

---

## License

Part of the Qubership Core Library for Go.

---

## Support

For issues and questions:
- Check the [Troubleshooting](#troubleshooting) section
- Review Kubernetes service account token configuration
- Verify network connectivity to Kubernetes API server
