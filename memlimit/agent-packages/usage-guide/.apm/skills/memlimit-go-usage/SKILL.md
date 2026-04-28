---
name: memlimit-go-usage
description: >
  Automatic GOMEMLIMIT configuration for Qubership Go microservices
  in Kubernetes. Use when creating a new service, debugging OOM kills,
  or configuring memory. Do NOT use for Helm chart resource limits.
---

# qubership-memlimit

Automatically sets Go runtime GOMEMLIMIT based on the container's
cgroup memory limit. Prevents OOM kills in Kubernetes by making
the Go GC aware of the container's memory boundary.

## Why it matters

Without GOMEMLIMIT the Go GC grows the heap freely until the
kernel OOM-killer terminates the process (exit code 137). This
library reads the cgroup limit and sets GOMEMLIMIT to a safe
fraction, so the GC runs more aggressively near the boundary.

## Import

Use a blank import — the library activates via its own `init()`,
there is no exported function to call:

```go
import _ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"
```

Place the import in `main.go`. Safe to use outside containers —
becomes a no-op when no cgroup limit is detected. Does not override
GOMEMLIMIT if already set via environment.

## Anti-patterns

```go
// WRONG: manual GOMEMLIMIT in Dockerfile
ENV GOMEMLIMIT=400MiB

// WRONG: direct runtime call
debug.SetMemoryLimit(400 * 1024 * 1024)

// WRONG: third-party library
import _ "github.com/KimMachineGun/automemlimit"
```