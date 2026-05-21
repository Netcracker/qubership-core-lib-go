# Rest Client

This package provides a REST client implementation for M2M communication with automatic authentication fallback to old approach support.

## Install

To install the rest client, use:

```bash
go get github.com/netcracker/qubership-core-lib-go/v3
```

## Override properties

| Configuration Property | Default Value | Description |
| --- | --- | --- |
| `security.m2m.kubernetes.enabled` | false | Enable k8s tokens authentication |
| `security.m2m.kubernetes.url-cache.internal-gateway-hostname` | internal-gateway-service | Hostname of the internal-gateway |

## Usage

The library offers three factory functions to create REST clients for different use cases:

### Factory Functions

* `NewM2MRestClient()` – returns a `*M2MRestClient` for internal service-to-service communication using Kubernetes tokens with Netcracker audience, with automatic fallback to Keycloak M2M tokens
* `NewDbaasRestClient()` – returns a `*M2MRestClient` for DBaaS communication using Kubernetes tokens with DBaaS audience, with automatic fallback to dbaas-agent
* `NewMaasRestClient()` – returns a `*M2MRestClient` for MaaS communication using Kubernetes tokens with MaaS audience, with automatic fallback to maas-agent

### Client Methods

```go
func (m *M2MRestClient) DoRequest(ctx context.Context, httpMethod, url string, headers map[string][]string, bodyReader io.Reader) (*http.Response, error)
```

## Examples

### Making Requests to Internal Services

```go
package main

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "strings"
    
    "github.com/netcracker/qubership-core-lib-go/v3/security/rest"
)

func main() {
    ctx := context.Background()
    
    // Create client for internal service communication
    client := rest.NewM2MRestClient()
    
    // Prepare headers
    headers := map[string][]string{
        "Content-Type": {"application/json"},
        "Accept":       {"application/json"},
    }
    
    // Prepare request body
    requestBody := `{"name":"example","value":123}`
    
    // Make POST request
    resp, err := client.DoRequest(
        ctx,
        http.MethodPost,
        "http://internal-service:8080/api/v1/resource",
        headers,
        strings.NewReader(requestBody),
    )
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    // Read response
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Status: %d\n", resp.StatusCode)
    fmt.Printf("Response: %s\n", string(body))
}
```

### Making GET Requests

```go
package main

import (
    "context"
    "fmt"
    "io"
    "net/http"
    
    "github.com/netcracker/qubership-core-lib-go/v3/security/rest"
)

func fetchData(ctx context.Context, resourceID string) error {
    client := rest.NewM2MRestClient()
    
    url := fmt.Sprintf("http://data-service:8080/api/v1/resources/%s", resourceID)
    
    resp, err := client.DoRequest(ctx, http.MethodGet, url, nil, nil)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read response: %w", err)
    }
    
    fmt.Printf("Data: %s\n", string(body))
    return nil
}
```

### Connecting to DBaaS

```go
package main

import (
    "context"
    "net/http"
    "strings"
    
    "github.com/netcracker/qubership-core-lib-go/v3/security/rest"
)

func createDatabase(ctx context.Context, dbName string) error {
    // Create client for DBaaS communication
    client := rest.NewDbaasRestClient()
    
    headers := map[string][]string{
        "Content-Type": {"application/json"},
    }
    
    requestBody := fmt.Sprintf(`{"name":"%s","type":"postgresql"}`, dbName)
    
    resp, err := client.DoRequest(
        ctx,
        http.MethodPost,
        "http://some-service:8080/databases",
        headers,
        strings.NewReader(requestBody),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusCreated {
        return fmt.Errorf("failed to create database: status %d", resp.StatusCode)
    }
    
    return nil
}
```

### Connecting to MaaS

```go
package main

import (
    "context"
    "net/http"
    "strings"
    
    "github.com/netcracker/qubership-core-lib-go/v3/security/rest"
)

func sendMessage(ctx context.Context, topic, message string) error {
    // Create client for MaaS communication
    client := rest.NewMaasRestClient()
    
    headers := map[string][]string{
        "Content-Type": {"application/json"},
    }
    
    requestBody := fmt.Sprintf(`{"topic":"%s","message":"%s"}`, topic, message)
    
    resp, err := client.DoRequest(
        ctx,
        http.MethodPost,
        "http://some-service:8080/messages",
        headers,
        strings.NewReader(requestBody),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    return nil
}
```

### Making Requests with Custom Headers

```go
package main

import (
    "context"
    "net/http"
    
    "github.com/netcracker/qubership-core-lib-go/v3/security/rest"
)

func fetchWithCustomHeaders(ctx context.Context) error {
    client := rest.NewM2MRestClient()
    
    // Add multiple custom headers
    headers := map[string][]string{
        "Content-Type":     {"application/json"},
        "Accept":           {"application/json"},
        "X-Request-ID":     {"12345"},
        "X-Correlation-ID": {"abc-def-ghi"},
    }
    
    resp, err := client.DoRequest(
        ctx,
        http.MethodGet,
        "http://api-service:8080/api/v1/data",
        headers,
        nil,
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    return nil
}
```

## Authentication Fallback

The REST client automatically handles authentication method selection:

1. **Primary Method**: On the first request to a service, the client attempts to use Kubernetes tokens with the appropriate audience
2. **Automatic Fallback**: If Kubernetes token authentication fails (token unavailable, acquisition error, or 401 Unauthorized response), the client automatically falls back to the legacy authentication method
3. **Caching**: Once a fallback is triggered for a service, subsequent requests to that service will directly use the fallback method to avoid unnecessary retries

This ensures backward compatibility with services that haven't been upgraded to support Kubernetes token authentication while providing seamless migration path for services that do support it.

## Testing
Override rest.DefaultDbaasAgentUrl and rest.DefaultMaasAgentUrl for testing.
