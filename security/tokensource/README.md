# Token Source

`tokensource` is a Go package that provides automatic management and refreshing of Kubernetes service account tokens. It watches token files for changes and maintains an in-memory cache, ensuring your application always has access to fresh, valid tokens without manual intervention.

## Features

- **Automatic Token Refresh** - Monitors token files and automatically updates cached tokens when Kubernetes rotates them
- **Audience-Specific Tokens** - Support for custom audience tokens via Kubernetes projected volumes
- **In-Memory Caching** - Fast token retrieval with thread-safe caching
- **Thread-Safe** - Concurrent access to tokens is fully supported
- **File System Watching** - Uses `fsnotify` to detect token updates in real-time
- **Lazy Initialization** - Token watchers are initialized only when first accessed

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Usage Guide](#usage-guide)
  - [Service Account Tokens](#service-account-tokens)
  - [Audience-Specific Tokens](#audience-specific-tokens)
  - [Custom Token Directories](#custom-token-directories)
- [How It Works](#how-it-works)
- [API Reference](#api-reference)
- [Best Practices](#best-practices)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Installation

```bash
go get github.com/netcracker/qubership-core-lib-go/v3
```

## Quick Start

### Default Service Account Token

```go
package main

import (
    "context"
    "fmt"
    
    "github.com/netcracker/qubership-core-lib-go/v3/tokensource"
)

func main() {
    ctx := context.Background()
    
    // Get the default Kubernetes service account token
    token, err := tokensource.GetServiceAccountToken(ctx)
    if err != nil {
        panic(err)
    }
}
```

### Audience-Specific Token

```go
package main

import (
    "context"
    "fmt"
    
    "github.com/netcracker/qubership-core-lib-go/v3/tokensource"
)

func main() {
    ctx := context.Background()
    
    // Get a token with a specific audience
    token, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
    if err != nil {
        panic(err)
    }
}
```

## Core Concepts

### Token Types

The package supports two types of Kubernetes tokens:

1. **Service Account Token** - The default token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. **Audience Tokens** - Custom audience tokens mounted via Kubernetes projected volumes at `/var/run/secrets/tokens/<audience>/token`

### File System Watching

The package uses `fsnotify` to watch token directories for changes. When Kubernetes rotates tokens, it updates the `..data` symbolic link, which triggers a cache refresh.

### Lazy Initialization

Token watchers are created on-demand when you first call `GetServiceAccountToken()` or `GetAudienceToken()`. This ensures minimal resource usage if tokens aren't needed.

### Thread-Safe Caching

All token operations are thread-safe:
- Audience tokens use `sync.Map` for concurrent read/write access
- Service account token uses `atomic.Value` for lock-free reads
- Watcher initialization uses `atomic.Pointer` with `utils.Lazy` for safe single initialization

## Usage Guide

### Service Account Tokens

The default Kubernetes service account token is automatically mounted into pods at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

#### Basic Usage

```go
import (
    "context"
    "github.com/netcracker/qubership-core-lib-go/v3/tokensource"
)

func authenticateRequest(ctx context.Context) error {
    // Always get a fresh token - never store it
    token, err := tokensource.GetServiceAccountToken(ctx)
    if err != nil {
        return fmt.Errorf("failed to get token: %w", err)
    }
    
    // Use the token for authentication
    req.Header.Set("Authorization", "Bearer " + token)
    
    return nil
}
```

#### Using with HTTP Clients

```go
import (
    "context"
    "net/http"
    
    "github.com/netcracker/qubership-core-lib-go/v3/tokensource"
)

func makeAuthenticatedRequest(ctx context.Context, url string) (*http.Response, error) {
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    // Get fresh token
    token, err := tokensource.GetServiceAccountToken(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to get service account token: %w", err)
    }
    
    // Add to request
    req.Header.Set("Authorization", "Bearer " + token)
    
    client := &http.Client{}
    return client.Do(req)
}
```

### Audience-Specific Tokens

Kubernetes projected volumes allow you to request tokens with specific audiences. This is useful for service-to-service authentication.

#### Getting Audience Tokens

Use `GetAudienceToken` method with one of the predefined audiences.

```go
import (
    "context"
    "fmt"
    
    "github.com/netcracker/qubership-core-lib-go/v3/tokensource"
)

func callDownstreamService(ctx context.Context) error {
    // Get token for specific audience
    token, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceDBaaS)
    if err != nil {
        return fmt.Errorf("failed to get audience token: %w", err)
    }
    
    // Use token for service-to-service authentication
    req.Header.Set("Authorization", "Bearer " + token)
    
    return nil
}
```

#### Multiple Audiences

```go
func callMultipleServices(ctx context.Context) error {
    // Get token for first service
    token1, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
    if err != nil {
        return err
    }
    
    // Get token for second service
    token2, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceMaaS)
    if err != nil {
        return err
    }
    
    // Use tokens...
    callServiceA(token1)
    callServiceB(token2)
    
    return nil
}
```

### Custom Token Directories

For testing or non-standard deployments, you can override the default token directories.

#### Override Audience Tokens Directory

```go
import "github.com/netcracker/qubership-core-lib-go/v3/tokensource"

func init() {
    // Override default audience tokens directory
    tokensource.DefaultAudienceTokensDir = "/custom/path/to/tokens"
}

func main() {
    ctx := context.Background()
    
    // Will now look for tokens in /custom/path/to/tokens
    token, err := tokensource.GetAudienceToken(ctx, "my-audience")
    // ...
}
```

#### Override Service Account Directory

```go
import "github.com/netcracker/qubership-core-lib-go/v3/tokensource"

func main() {
    ctx := context.Background()
    
    // Override default service account directory
    tokensource.DefaultServiceAccountDir = "/custom/serviceaccount"
    
    // Will now look for token at /custom/serviceaccount/token
    token, err := tokensource.GetServiceAccountToken(ctx)
    // ...
}
```

## How It Works

### Initialization Flow

1. **First Call**: When you first call `GetServiceAccountToken()` or `GetAudienceToken()`, a lazy initializer creates a token watcher
2. **Initial Load**: The watcher reads all token files from the directory and populates the cache
3. **File Watch Setup**: An `fsnotify` watcher is created to monitor the directory for changes
4. **Background Monitoring**: A goroutine continuously listens for file system events

### Token Refresh Flow

1. **Kubernetes Rotation**: Kubernetes rotates the token by updating the `..data` symbolic link
2. **Event Detection**: The `fsnotify` watcher detects a `CREATE` event for `..data`
3. **Cache Update**: The token watcher reads the new token file(s) and updates the cache
4. **Immediate Availability**: The next call to `GetServiceAccountToken()` or `GetAudienceToken()` returns the fresh token

### Directory Structure

**Service Account Token:**
```
/var/run/secrets/kubernetes.io/serviceaccount/
├── ca.crt
├── namespace
├── token          <- Monitored file
└── ..data -> ...  <- Watched for changes
```

**Audience Tokens:**
```
/var/run/secrets/tokens/
│   ..data -> ...  <- Watched for changes
├── audience-1/
│   ├── token          <- Monitored file
└── audience-2/
    ├── token          <- Monitored file
```

## Best Practices

### 1. Never Store Tokens

**Don't do this:**
```go
// BAD: Storing token for reuse
var cachedToken string

func init() {
    token, _ := tokensource.GetServiceAccountToken(context.Background())
    cachedToken = token // Token will become stale!
}

func makeRequest() {
    req.Header.Set("Authorization", "Bearer " + cachedToken)
}
```

**Do this instead:**
```go
// GOOD: Always get fresh token
func makeRequest(ctx context.Context) error {
    token, err := tokensource.GetServiceAccountToken(ctx)
    if err != nil {
        return err
    }
    
    req.Header.Set("Authorization", "Bearer " + token)
    return nil
}
```

### 2. Handle Errors Gracefully

```go
func authenticatedRequest(ctx context.Context) error {
    token, err := tokensource.GetServiceAccountToken(ctx)
    if err != nil {
        // Log error with context
        log.Errorf("Failed to get service account token: %v", err)
        
        // Return meaningful error
        return fmt.Errorf("authentication failed: %w", err)
    }
    
    // Use token...
    return nil
}
```

### 3. Use Context for Lifecycle Management

```go
func runWorker(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            // Get fresh token on each iteration
            token, err := tokensource.GetServiceAccountToken(ctx)
            if err != nil {
                log.Errorf("Failed to refresh token: %v", err)
                continue
            }
            
            // Perform work with token...
            doWork(token)
            
        case <-ctx.Done():
            // Cleanup happens automatically
            return
        }
    }
}
```

### 4. Validate Audience Names

```go
func getAudienceToken(ctx context.Context, audience string) (string, error) {
    // Validate input
    if audience == "" {
        return "", fmt.Errorf("audience cannot be empty")
    }
    
    // Optionally validate against expected audiences
    validAudiences := map[string]bool{
        "service-a": true,
        "service-b": true,
    }
    
    if !validAudiences[audience] {
        return "", fmt.Errorf("invalid audience: %s", audience)
    }
    
    return tokensource.GetAudienceToken(ctx, audience)
}
```

### 5. Use Proper Logging

```go
import "github.com/netcracker/qubership-core-lib-go/v3/logging"

var logger = logging.GetLogger("my-service")

func makeAuthenticatedCall(ctx context.Context) error {
    logger.Debug("Retrieving service account token")
    
    token, err := tokensource.GetServiceAccountToken(ctx)
    if err != nil {
        logger.Errorf("Failed to get service account token: %v", err)
        return err
    }
    
    logger.Debug("Token retrieved successfully")
    
    // Use token...
    return nil
}
```

### 6. Consider Token Expiration

```go
// For long-running operations, periodically refresh
func longRunningOperation(ctx context.Context) error {
    for {
        // Get fresh token at the start of each iteration
        token, err := tokensource.GetServiceAccountToken(ctx)
        if err != nil {
            return err
        }
        
        // Perform operation with fresh token
        err = performOperationWithToken(ctx, token)
        if err != nil {
            return err
        }
        
        // Sleep before next iteration
        select {
        case <-time.After(1 * time.Minute):
            continue
        case <-ctx.Done():
            return ctx.Err()
        }
    }
}
```

## Troubleshooting

### Token Not Found Error

**Error:**
```
token with audience netcracker was not found
```

**Causes:**
1. Token directory doesn't exist
2. Token wasn't mounted via projected volume
3. Audience name mismatch

### Failed to Read Token Error

**Error:**
```
failed to read token at path /var/run/secrets/kubernetes.io/serviceaccount/token: permission denied
```

**Causes:**
1. Insufficient file permissions
2. Service account not properly mounted
3. Running outside Kubernetes cluster

**Debugging:**
```go
import "github.com/netcracker/qubership-core-lib-go/v3/logging"

// Enable debug logging
logging.SetLevel("token-file-storage", logging.DEBUG)

// Check logs for refresh events
// You should see: "k8s tokens updated: started refreshing k8s tokensCache"
//                 "k8s tokensCache refreshed"
```

**Solutions:**
1. Ensure `..data` symbolic link is being updated by Kubernetes
2. Verify file watcher has proper permissions
3. Check that token directory is correctly mounted

## Summary

The `tokensource` package provides a robust, production-ready solution for managing Kubernetes service account tokens in Go applications. Key takeaways:

- Always call `GetServiceAccountToken()` or `GetAudienceToken()` to get fresh tokens
- Never store tokens - the package handles caching and refresh automatically
- Use context for proper lifecycle management
- Handle errors gracefully and log appropriately
- Override default directories for testing

For more information, see the [Kubernetes documentation on service account tokens](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/).
