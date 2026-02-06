# memlimit

`memlimit` initializes Go's memory limit (refer to `GOMEMLIMIT`) at process startup using
the container cgroup limit via `github.com/KimMachineGun/automemlimit`.

The package runs during `init()` when imported and logs whether a limit was set.

## Installation

```bash
go get github.com/netcracker/qubership-core-lib-go/v3
```

## Usage

Import the package to apply the limit on startup:

```go
package main

import (
	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"
)

func main() {
	// Application logic.
}
```

## Behavior

- Uses `automemlimit` defaults (ratio `0.9`, provider `FromCgroup`).
- Logs whether memory limit  was set.
- Requires Linux cgroup limits - if not available or unlimited - no limit will be applied;