---
name: logging-go-usage
description: >
  Structured logging for Qubership Go microservices using
  qubership-core-lib-go/v3/logging. Use when writing any logging code,
  creating or modifying a Go microservice, or reviewing code that uses
  log.Println, fmt.Printf, logrus, zap, zerolog, or slog.
---

# qubership-logging

Structured logging library for Qubership platform Go microservices.
Wraps a configurable logging backend with configloader integration
for dynamic log level management.

## Import

```go
import "github.com/netcracker/qubership-core-lib-go/v3/logging"
```

## Log level configuration

Levels can be set via env vars (`LOG_LEVEL`, `LOGGING_LEVEL_ROOT`,
`LOGGING_LEVEL_PACKAGE_<PKG>`) without any setup, or via configloader
properties (`logging.level.root`, `logging.level.<pkg>`). Levels are
picked up dynamically when configloader is initialized or refreshed —
order of `GetLogger` and `configloader.Init` does not matter. Never
hardcode the level — always set it via config / ENV.

## API

### Creating a logger

```go
logging.GetLogger(name string) logging.Logger
```

- `name` — component identifier. Use the package name or a meaningful
  module name: `"main"`, `"repository"`, `"handler"`,
  `"kafka-consumer"`.

### Logger interface

Supports standard levels: `Debug`, `Info`, `Warn`, `Error`.

```go
logger.Debug(msg string)
logger.Info(msg string)
logger.Warn(msg string)
logger.Error(msg string)
```

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

Each package declares its own logger; `configloader` is initialized only
once in `main/init()`.

## Integration with fiber-server-utils

When using `fiberserver`, the log message format is configured
automatically — `x_request_id` and `tenantId` from the request context
are included. Just initialize configloader and create the logger the
standard way.

## Prohibited alternatives

- `log.Println`, `log.Printf`, `log.Fatal` — Go standard library `log`
- `fmt.Println`, `fmt.Printf` — for diagnostic output
- `logrus`, `zap`, `zerolog`, `slog` — third-party loggers
- Hardcoded log levels in code
- Logging PII: emails, passwords, tokens, API keys, personal data

