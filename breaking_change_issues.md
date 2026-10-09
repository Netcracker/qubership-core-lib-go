# This document contains issues and tasks which break backward compatibility.

## [ON HOLD] Incoming headers must be case-insensitive

Header names which we get from incoming data are case-sensitive.
This means that it is impossible to know about the presence of the header in incoming data,
because the exact format of the header cannot be known.

#### Solution:

Convert all header names in incoming data to lowercase before searching for headers.

## Changed log levels configuration format

The new format of log level configuration properties was introduced.

### Old approach (deprecated)
For env:
```yaml
LOG_LEVEL=debug
LOG_LEVEL_PACKAGE_DBAAS=warn
```

For yaml:
```yaml
log.level: debug
log.level.package:
  dbaas: warn
```

### New approach

For env:
```yaml
LOGGING_LEVEL_ROOT=debug
LOGGING_LEVEL_DBAAS=warn
```

For yaml:
```yaml
logging.level.root: debug
logging.level:
  dbaas: warn
```

The old approach is deprecated and will be removed according to deprecation policy.

## utils.GetTransport keeps the standard library defaults

`GetTransport` built its transport from a literal in order to set `TLSClientConfig`, which left
every other field at its zero value. A zero value is not a default: `http.Client` only falls back
to `http.DefaultTransport` when no transport is given at all, and that default configures seven
fields the literal did not.

Callers of `GetTransport` and `GetClient` therefore held idle connections for the lifetime of the
transport, dialled without a timeout or TCP keep-alive, ignored `HTTP_PROXY`, `HTTPS_PROXY` and
`NO_PROXY`, and never negotiated HTTP/2, since a custom `TLSClientConfig` disables the automatic
upgrade unless `ForceAttemptHTTP2` is set.

### Solution

Clone the standard transport and override the one field that has to differ:

```go
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.TLSClientConfig = GetTlsConfig()
```

Two behaviours change for every caller. HTTP/2 becomes negotiable where it was not, and a proxy
configured in the environment starts being honoured. Both are corrections, but a service that
relied on the previous behaviour will see the difference.