---
name: logging-go-usage
description: Use when writing or replacing logging in a Qubership Go microservice — `qubership-core-lib-go/v3/logging` instead of `log`/`fmt`/logrus/zap/zerolog/slog.
---

# qubership-logging

Structured logging library for Qubership platform Go microservices.
Wraps a configurable logging backend with configloader integration
for dynamic log level management.

## Log level configuration

Levels can be set via env vars (`LOG_LEVEL`, `LOGGING_LEVEL_ROOT`,
`LOGGING_LEVEL_PACKAGE_<PKG>`) without any setup, or via configloader
properties (`logging.level.root`, `logging.level.<pkg>`). Levels are
picked up dynamically when configloader is initialized or refreshed —
order of `GetLogger` and `configloader.Init` does not matter. Never
hardcode the level — always set it via config / ENV.

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

Each package declares its own logger named after the package or module
(`main`, `repository`, `handler`, `kafka-consumer`); `configloader` is
initialized only once in `main/init()`.

## Integration with fiber-server-utils

When using `fiberserver`, the log message format is configured
automatically — `x_request_id` and `tenantId` from the request context
are included. Just initialize configloader and create the logger the
standard way.

## Rules

- Use only `qubership-core-lib-go/v3/logging` — replaces `log`, `fmt.Print*`, `logrus`, `zap`, `zerolog`, `slog`.
- Never log PII (emails, passwords, tokens, API keys, personal data).

