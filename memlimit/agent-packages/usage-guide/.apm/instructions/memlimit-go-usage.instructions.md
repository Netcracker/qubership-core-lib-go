---
description: >
  Require memlimit.SetMemoryLimit() in every Qubership Go microservice.
applyTo: "**/main.go"
---

# memlimit requirement

Every Qubership microservice must call memlimit.SetMemoryLimit()
in main package init(), after configloader and logger init.

```go
import "github.com/netcracker/qubership-core-lib-go/v3/memlimit"
```

Do not set GOMEMLIMIT manually. Do not use automemlimit
or runtime/debug.SetMemoryLimit() directly.