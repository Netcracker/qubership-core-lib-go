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

Place the import in `main.go`.

## Requirements

- `application.yaml` must exist in the working directory before the
  binary starts (empty file is fine) — without it the service fails
  to start.
- Outside containers (local dev, macOS) cgroup files are absent, so
  the library logs a warning and skips setting the limit; the service
  continues normally.

## Guidelines

- Use `qubership-core-lib-go/v3/memlimit` (it wraps `automemlimit` with
  Qubership defaults); don't import `automemlimit` directly.
- Don't set `GOMEMLIMIT` manually in Dockerfile or call
  `debug.SetMemoryLimit` — the library handles it from the cgroup.