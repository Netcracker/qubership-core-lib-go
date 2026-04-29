---
description: Go coding standards for Qubership Logging
applyTo: "**/*.go"
---

# Qubership Logging

Only allowed logger: github.com/netcracker/qubership-core-lib-go/v3/logging

Prohibited: log, fmt.Println, logrus, zap, zerolog, slog.
Declare logger at package level. Initialize configloader before GetLogger.
Never log PII (passwords, tokens, emails).
