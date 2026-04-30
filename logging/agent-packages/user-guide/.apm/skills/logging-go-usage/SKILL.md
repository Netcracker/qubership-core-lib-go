---
name: logging-go-usage
description: >
  Structured logging for Qubership Go microservices using
  qubership-core-lib-go/v3/logging. Use when writing any logging code,
  creating or modifying a Go microservice, or reviewing code that uses
  log.Println, fmt.Printf, logrus, zap, zerolog, or slog.
  Do NOT use for qubership-logging-operator (Kubernetes infrastructure).
---

# qubership-logging

Structured logging library for Qubership platform Go microservices.
Wraps a configurable logging backend with configloader integration
for dynamic log level management.

## Import

```go
import "github.com/netcracker/qubership-core-lib-go/v3/logging"
```

## Dependency on configloader

configloader MUST be initialized **before** calling `GetLogger`.
Without it the logger will not pick up level configuration and
will fall back to defaults, ignoring `log.level` settings.

```go
import "github.com/netcracker/qubership-core-lib-go/v3/configloader"
```

## API

### Creating a logger

```go
logging.GetLogger(name string) logging.Logger
```

- `name` — component identifier. Use the package name or a meaningful
  module name: `"main"`, `"repository"`, `"handler"`,
  `"kafka-consumer"`.
- Returns `logging.Logger` — an interface with level-based methods.

### Logger interface

Supports standard levels: `Debug`, `Info`, `Warn`, `Error`.

```go
logger.Debug(msg string)
logger.Info(msg string)
logger.Warn(msg string)
logger.Error(msg string)
```

### Level management

Log level is controlled via configloader. Configuration keys:

- `log.level` — global level for the entire application
- `log.level.<logger-name>` — level for a specific logger

Values: `debug`, `info`, `warn`, `error`.
Never hardcode the level — it is managed through config / ENV.

## Canonical usage pattern

```go
package main

import (
    "github.com/netcracker/qubership-core-lib-go/v3/configloader"
    "github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var logger logging.Logger

func init() {
    configloader.InitWithSourcesArray(configloader.BasePropertySources())
    logger = logging.GetLogger("main")
}

func main() {
    logger.Info("Service started")

    if err := run(); err != nil {
        logger.Error("Service failed: " + err.Error())
    }
}
```

Key points:
1. `var logger` — declared at package level
2. `configloader.InitWithSourcesArray(...)` — called in `init()`, first
3. `logging.GetLogger(...)` — called in `init()`, after configloader
4. Logger name matches the package name

## Usage across multiple packages

Each package declares its own logger. configloader is initialized
only once, in `main/init()`.

```go
// package repository
package repository

import "github.com/netcracker/qubership-core-lib-go/v3/logging"

var logger = logging.GetLogger("repository")

func FindByID(id string) (*Entity, error) {
    logger.Debug("Finding entity by ID: " + id)
    // ...
}
```

## Integration with fiber-server-utils

When using `fiberserver`, the log message format is configured
automatically — `x_request_id` and `tenantId` from the request
context are included. Just initialize configloader and create the
logger the standard way.

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/configloader"
    "github.com/netcracker/qubership-core-lib-go/v3/logging"
    fiberserver "github.com/netcracker/qubership-core-lib-go-fiber-server-utils/v2"
)

var logger logging.Logger

func init() {
    configloader.InitWithSourcesArray(configloader.BasePropertySources())
    logger = logging.GetLogger("main")
}
```

## Prohibited alternatives

- `log.Println`, `log.Printf`, `log.Fatal` — Go standard library `log`
- `fmt.Println`, `fmt.Printf` — for diagnostic output
- `logrus`, `zap`, `zerolog`, `slog` — third-party loggers
- Hardcoded log levels in code
- Logging PII: emails, passwords, tokens, API keys, personal data

## Anti-patterns

```go
// WRONG: standard log
log.Println("something happened")

// WRONG: fmt for diagnostics
fmt.Printf("error: %v\n", err)

// WRONG: logger without configloader
func init() {
    logger = logging.GetLogger("main") // configloader not initialized!
}

// WRONG: creating logger inside a function
func handleRequest() {
    l := logging.GetLogger("handler") // declare at package level!
    l.Info("handling request")
}

// WRONG: logging secrets
logger.Info("Auth token: " + token)
logger.Debug("User email: " + user.Email)
```