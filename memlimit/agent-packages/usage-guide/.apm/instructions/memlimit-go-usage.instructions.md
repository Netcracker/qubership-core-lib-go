---
description: Automatic GOMEMLIMIT configuration for Qubership Go microservices in Kubernetes.
applyTo: "**/main.go"
---

# memlimit requirement

Every Qubership microservice must include memlimit via blank import
in main.go. The library activates through its own init() — there is
no function to call.

```go
import _ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"
```

Do not set GOMEMLIMIT manually. Do not use automemlimit
or runtime/debug.SetMemoryLimit() directly.