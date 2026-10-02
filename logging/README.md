# Logger

This package is intended for logging. It provides different log levels, two output formats (text and JSON),
structured key/value fields, the ability to customize the log format, and to change the log level and log format
during runtime.

- [Logger](#logger)
  - [Install](#install)
  - [Setup logger](#setup-logger)
  - [Log levels](#log-levels)
    - [Log with context](#log-with-context)
  - [Log Level Settings](#log-level-settings)
    - [Bootstrap phase configuration](#bootstrap-phase-configuration)
    - [Runtime phase configuration](#runtime-phase-configuration)
    - [How to define log levels](#how-to-define-log-levels)
  - [Log format](#log-format)
    - [Text format](#text-format)
    - [JSON format](#json-format)
    - [How to select the format](#how-to-select-the-format)
  - [Structured fields](#structured-fields)
    - [Inline fields](#inline-fields)
    - [Scoped fields with With](#scoped-fields-with-with)
    - [Field values](#field-values)
    - [Malformed argument lists](#malformed-argument-lists)
  - [Custom context fields](#custom-context-fields)
  - [Output destination](#output-destination)
  - [Custom Formatting](#custom-formatting)
  - [Custom Formatting per logger](#custom-formatting-per-logger)
  - [Change log level by http request](#change-log-level-by-http-request)
  - [Change log format by http request](#change-log-format-by-http-request)
  - [Get all current log levels](#get-all-current-log-levels)
  - [Migrating to JSON](#migrating-to-json)
    - [Phase 1: flip the format, change no code](#phase-1-flip-the-format-change-no-code)
    - [Phase 2: promote message values to fields](#phase-2-promote-message-values-to-fields)
  - [Compatibility](#compatibility)

## Install

To install `logger` use

```go
 go get github.com/netcracker/qubership-core-lib-go/v3@<latest released version>
```

## Setup logger

To get a logger use func `GetLogger` and pass the correct package name as a parameter. You may create the logger in an
_init_ function.

For example, a logger for everything located in the dbaas package looks like:

```go
package main

import "github.com/netcracker/qubership-core-lib-go/v3/logging"

var logger logging.Logger

func init() {
	logger = logging.GetLogger("dbaas")
}
```

To also use [structured fields](#structured-fields), use `GetFieldLogger` instead. It returns the very same logger
object, only typed as `FieldLogger`, so every method shown in this document is available:

```go
var logger logging.FieldLogger

func init() {
	logger = logging.GetFieldLogger("dbaas")
}
```

**Note:** It is highly recommended using this package with [configloader package](../configloader/README.md),
because configloader allows configuring the logging process with an application.yaml file. It means that your `main`
function should call the code:

```go
  configloader.Init(configloader.BasePropertySource())
```

## Log levels

The logger interface defines 5 levels of logging: `Debug`, `Info`, `Warn`, `Error` and `Panic`.
These accept a format string and variadic arguments.

Additionally, each of the log levels offers an explicitly named formatted variant: `Debugf`, `Infof`, `Warnf`, `Errorf`
and `Panicf`. These are aliases of the base methods -- both behave like `fmt.Printf` and offer the ability to define a
format string and parameters to populate it.

_Note, that all logger messages with Panic level will first log a critical event and then panic with the message from
the logger._

Examples:

```go
    log := logging.GetLogger("main")
    log.Info("This is info string")
    log.Infof("This is %s string with %f parameter", "formatted", 7.2)
    log.Errorf("This is error string with %s parameter", "parameter")
    log.Panic("This log will create panic with this message")
```

### Log with context

For each log level there is a possibility to log a message with a context (it should be a context.Context): `DebugC`,
`InfoC`, `WarnC`, `ErrorC` and `PanicC`.

Information carried by the context is added to the log output automatically -- request id, tenant id and channel
request id are part of the default format and require no configuration. They are populated by the
[context-propagation](../context-propagation/README.md) package.

```go
    log.DebugC(ctx, "teststring %s, %s", "one", "two")
```

## Log Level Settings

Please read this section very attentively in order not to have problems with logging.

The logger has two phases: `logger's bootstrap time` and `logger's runtime`. The main difference between them is the
different process of configuration loading. The logger usually gets configuration from configloader, but there are no
properties during the logger's bootstrap time because configloader is not initialized yet. The logger's bootstrap time
ends when `configloader is initialized`.

**Default level for all phases is INFO.** If you want to use the default level, don't provide any properties at all.

### Bootstrap phase configuration

During the logger's bootstrap phase you may use the default level or configure the log level with the environment. You
may configure the global log level with variable `LOGGING_LEVEL_ROOT` or configure the level for a specific package with
variable `LOGGING_LEVEL_<package_name>`.

Example: how to set global `warn` lvl and `debug` lvl for the `dbaas` package during the bootstrap phase.

```properties
    LOGGING_LEVEL_ROOT=warn
    LOGGING_LEVEL_DBAAS=debug
```

### Runtime phase configuration

During the logger's runtime phase you may use the default level or configure the level with application.yaml or with
environment variables.

To override the default level and set a new level for all packages use property `logging.level.root` with
application.yaml or environment variable `LOGGING_LEVEL_ROOT`.

> **_NOTE:_**  You can configure the logger through `application.yaml` and `environment` if you provide and initialize
> configloader with these property sources.
> For example `configloader.Init(configloader.BasePropertySource())`. Pay attention that you have to call the
> configloader#Init method only once and in your main function as early as possible.

Example: how to set global `debug` level.

_application.yaml_

```yaml
  logging.level.root: debug
```

or

_Environment variables_

```yaml
  LOGGING_LEVEL_ROOT=debug
```

Also, it is possible to set the log level for a specific package. You may do it with property `logging.level` with
application.yaml or with environment variables `LOGGING_LEVEL_<package-name>`.

Example: how to set `warn` lvl for package dbaas and `error` level for contextpropagation.

_application.yaml_

```yaml
    logging.level:
        dbaas: warn
        contextpropagation: error
```

or

_Environment_

```yaml
    LOGGING_LEVEL_DBAAS=warn
    LOGGING_LEVEL_CONTEXTPROPAGATION=error
```

**Note** that the package level overrides the global level. So in the below example all packages except dbaas will have
`warn` level, and dbaas will have `debug` level.

```yaml
  logging.level.root: warn
  logging.level:
      dbaas: debug
```

### How to define log levels

You may use any case: lower or upper. If the level value is incorrect, the logger will use the default level.

| Desired log level | Property value |
| ----------------- | -------------- |
| Panic             | fatal          |
| Error             | error          |
| Warn              | warn           |
| Info              | info           |
| Debug             | debug          |

## Log format

The logger supports two output formats: `text` (the default) and `json`.

### Text format

The default format produces one bracketed line per record:

```bash
[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] order placed
```

| Segment                | Source                                                                  |
| ---------------------- | ----------------------------------------------------------------------- |
| timestamp              | record time, layout `2006-01-02T15:04:05.000`                           |
| level                  | `FATAL`, `ERROR`, `WARN`, `INFO` or `DEBUG`                             |
| `request_id`           | context value `X-Request-Id`                                            |
| `tenant_id`            | context value `Tenant-Context`                                          |
| `thread`               | always `-`; the field exists for compatibility with Java logs           |
| `class`                | logger name, plus `.<caller>` when the context carries `caller`         |
| `x_channel_request_id` | context value `X-Channel-Request-Id`                                    |
| message                | the formatted message, then any [structured fields](#structured-fields) |

A context value that is absent, or whose type is neither `string` nor an implementation of
`ContextObjectLogValueGetter`, renders as the `-` placeholder.

### JSON format

The JSON format emits one JSON document per line, with the same set of fields:

```json
{"time":"2026-07-30T10:15:03.123","level":"INFO","message":"order placed","request_id":"-","tenant_id":"-","thread":"-","class":"orders","x_channel_request_id":"-","order_id":42}
```

Key order is fixed: `time`, `level` and `message` come first so a raw line stays readable in a terminal without `jq`,
followed by the context fields, then any [custom context fields](#custom-context-fields), then any
[structured fields](#structured-fields).

Notes:

- Absent values are emitted as the string `"-"`, not `null`, matching the text format.
- Field values are typed: numbers and booleans are emitted as JSON numbers and booleans, not as strings.
- Avoid naming a structured field after a reserved key (`message`, `level`, ...). Duplicates are emitted as-is; the
  document remains valid, but most parsers keep only the last occurrence.

### How to select the format

Use property `logging.format` or environment variable `LOGGING_FORMAT`, with the value `text` or `json`. The value is
case-insensitive. Anything unrecognised falls back to `text`.

Resolution follows the same two phases as the log level:

| Phase                                          | Source                                |
| ---------------------------------------------- | ------------------------------------- |
| Bootstrap (before configloader is initialized) | environment variable `LOGGING_FORMAT` |
| Runtime (after configloader is initialized)    | property `logging.format`             |

_Environment_

```properties
    LOGGING_FORMAT=json
```

or

_application.yaml_

```yaml
    logging.format: json
```

The format is re-read whenever configloader is initialized or refreshed, so it can be changed without a restart. It can
also be set programmatically, or [changed over HTTP](#change-log-format-by-http-request):

```go
    logging.SetOutputFormat(logging.FormatJSON)

    logging.GetOutputFormat()        // logging.FormatJSON
    logging.GetOutputFormat().String() // "json"
```

> **_NOTE:_** A format set programmatically or over HTTP is _explicit_ and wins over configuration: a later
> configloader refresh will not silently revert it. `logging.IsOutputFormatExplicit()` reports whether that is the case,
> which is the first thing to check if a configured format appears not to take effect.

## Structured fields

Structured fields let you attach typed key/value pairs to a record instead of interpolating them into the message. In
JSON format each pair becomes a top-level key; in text format they are appended after the message in logfmt style.

The API lives on `FieldLogger`, obtained with `GetFieldLogger`:

```go
log := logging.GetFieldLogger("orders")
```

If you only hold a `logging.Logger` -- for example one injected as a dependency -- adapt it with `logging.Fields`:

```go
logging.Fields(someLogger).InfoW("order placed", "order_id", 42)
```

> **_NOTE:_** Unlike the printf-style methods, the `msg` argument of the `*W` methods is a **literal**. It is never
> passed through `fmt.Sprintf`, so it may contain `%` freely.

### Inline fields

Each level has a `W` method and a context-aware `WC` variant: `DebugW`/`DebugWC`, `InfoW`/`InfoWC`, `WarnW`/`WarnWC`,
`ErrorW`/`ErrorWC`, `PanicW`/`PanicWC`. Arguments after the message are alternating keys and values.

```go
log.InfoWC(ctx, "order placed", "order_id", 42, "customer", "acme", "express", true)
```

_text_

```bash
[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] order placed order_id=42 customer=acme express=true
```

_json_

```json
{"time":"2026-07-30T10:15:03.123","level":"INFO","message":"order placed","request_id":"-","tenant_id":"-","thread":"-","class":"orders","x_channel_request_id":"-","order_id":42,"customer":"acme","express":true}
```

In text format a value containing a space, `"`, `=` or a control character is quoted and escaped:

```go
log.InfoW("saved", "note", "two words")
// ... saved note="two words"
```

### Scoped fields with With

`With` returns a logger that adds the given pairs to every record it writes. The receiver is unchanged, so it is safe to
derive per-request or per-component loggers:

```go
log := logging.GetFieldLogger("orders").With("component", "checkout")

func handle(ctx context.Context, orderID int) {
	reqLog := log.With("order_id", orderID)

	reqLog.InfoWC(ctx, "processing")
	// ... processing component=checkout order_id=42
	reqLog.WarnWC(ctx, "retrying", "attempt", 2)
	// ... retrying component=checkout order_id=42 attempt=2
}
```

A derived logger is a **view** of the logger it came from, not an independent copy:

- Level, format and output destination are shared with the parent, so a level refresh or an HTTP level change reaches
  derived loggers too.
- Calling `SetLevel` on a derived logger changes the parent as well.
- Derived loggers are not registered, so they do not appear in [`GetLogLevels`](#get-all-current-log-levels).

### Field values

Values are rendered without reflection for the common types: `string`, `bool`, all integer and float widths, `[]byte`,
`nil`, `error` (rendered as `Error()`), `fmt.Stringer` (rendered as `String()`) and `ContextObjectLogValueGetter`
(rendered as `GetLogValue()`). Anything else is rendered with `fmt.Sprint` and emitted as a string.

`NaN` and infinities cannot be represented in JSON and are emitted as the strings `"NaN"`, `"+Inf"` and `"-Inf"`.

### Malformed argument lists

A malformed argument list never panics and never drops data. The offending value is logged under the key `!BADKEY`, so
the mistake is visible in the output instead of invisible in the code:

```go
log.InfoW("msg", "dangling")     // ... msg !BADKEY=dangling
log.InfoW("msg", 7, "k", "v")    // ... msg !BADKEY=7 k=v
```

## Custom context fields

Beyond the built-in context fields, you can declare additional context keys to be logged with every record, using a
template of `%{context-key}` placeholders:

```go
logging.DefaultFormat.SetCustomLogFields("[bp=%{business_process_id}] [ob=%{originating_bi_id}]")
```

Values are resolved from the record's context by key, exactly as the built-in fields are; a key that is absent renders
as `-`.

In **text** format the template is substituted and placed before the message:

```
[2026-07-30T10:15:03.123] [INFO] ... [x_channel_request_id=-] [bp=bp-1] [ob=-] order placed
```

In **json** format the literal text of the template is dropped and each placeholder name becomes a top-level key:

```json
{"time":"...","level":"INFO","message":"order placed","request_id":"-", ...,"business_process_id":"bp-1","originating_bi_id":"-"}
```

## Output destination

By default all loggers write to `os.Stdout`. This can be overridden globally or per logger, which is mostly useful in
tests:

```go
var buf bytes.Buffer

logging.SetOutput(&buf)          // every logger without its own destination
logging.SetOutput(nil)           // back to os.Stdout

logging.GetFieldLogger("orders").SetOutput(&buf)   // this logger only
```

A per-logger destination overrides the global one, and loggers derived with `With` share their parent's destination.

## Custom Formatting

If neither built-in format is suitable, there is a possibility to create your own format function. Use
`SetLogFormat(format func(r *Record) []byte)` and pass the new format function as a parameter.

> **_NOTE:_** Installing a custom format function makes the format _explicit_, so the `logging.format` property no
> longer applies. The function receives the whole `Record`, including `Record.Fields`; if it does not render them,
> [structured fields](#structured-fields) will not appear in its output.

Example: such formatting will produce logs in this format, and every log message will be light green coloured.
```go
package main

import (
  "bytes"
  "fmt"
  "strings"

  "github.com/netcracker/qubership-core-lib-go/v3/configloader"
  "github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var log logging.Logger

func customLogFormat(r *logging.Record) []byte {
  var color = 42
  TimeFormat := "2006-01-02"
  b := &bytes.Buffer{}
  lvl := strings.ToUpper(r.Lvl.String())

  fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m [packageName=%s] %s",
    r.Time.Format(TimeFormat),
    color,
    lvl,
    "main",
    r.Message,
  )

  b.WriteByte('\n')
  return b.Bytes()
}

func init() {
  configloader.InitWithSourcesArray(configloader.BasePropertySources())
  log = logging.GetLogger("main")
}

func main() {
  logging.SetLogFormat(customLogFormat)
  log.Info("log string")
}
```
Output is:

```
    [2026-07-30] [INFO] [packageName=main] log string
```

Also, you can set only a new message format. It may be useful when you need information about tenantId or requestId in
log messages. To set a new message format use func `SetMessageFormat`.

The below example will produce a log with a new message format, where a field with requestId is added. Note that context
values are read with `logging.GetValueOrPlaceholder` -- `r.Ctx` is a `context.Context`, so its values cannot be accessed
as struct fields.

```go
package main

import (
  "bytes"
  "context"
  "fmt"

  "github.com/netcracker/qubership-core-lib-go/v3/configloader"
  "github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var log logging.Logger

func customMessageFormat(r *logging.Record, b *bytes.Buffer, color int, lvl string) (int, error) {
  TimeFormat := "2006-01-02"
  return fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m [requestId=%s] [caller=%s] %s",
    r.Time.Format(TimeFormat),
    color,
    lvl,
    logging.GetValueOrPlaceholder(r.Ctx, logging.RequestIdContextName),
    "main",
    r.Message,
  )
}

func init() {
  configloader.InitWithSourcesArray(configloader.BasePropertySources())
  log = logging.GetLogger("main")
}

func main() {
  logging.DefaultFormat.SetMessageFormat(customMessageFormat)
  log.InfoC(context.Background(), "Log with request id")
}
```

Output is

```bash
[2026-07-30] [INFO] [requestId=123] [caller=main] Log with request id
```

## Custom Formatting per logger

If you need a different format depending on the logger, there is a possibility to create your own format function for a
particular logger. Use `SetLogFormat(format func(r *Record) []byte)` and pass the new format function as a parameter to
the logger.

Example: such formatting will produce logs in this format, and every log message for the "custom" logger will be light
green coloured.

```go
package main

import (
  "bytes"
  "fmt"
  "strings"

  "github.com/netcracker/qubership-core-lib-go/v3/configloader"
  "github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var mainLog logging.Logger
var customLog logging.Logger

func customLogFormat(r *logging.Record) []byte {
  var color = 42
  TimeFormat := "2006-01-02"
  b := &bytes.Buffer{}
  lvl := strings.ToUpper(r.Lvl.String())

  fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m [packageName=%s] %s",
    r.Time.Format(TimeFormat),
    color,
    lvl,
    "custom",
    r.Message,
  )

  b.WriteByte('\n')
  return b.Bytes()
}

func init() {
  configloader.InitWithSourcesArray(configloader.BasePropertySources())
  mainLog = logging.GetLogger("main")
  customLog = logging.GetLogger("custom")
}

func main() {
  customLog.SetLogFormat(customLogFormat)
  mainLog.Info("mainLog string")
  customLog.Info("customLog string")
}
```

Output is:

```bash
[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=main] [x_channel_request_id=-] mainLog string
[2026-07-30] [INFO] [packageName=custom] customLog string
```

A per-logger format overrides both the global custom format and the configured `logging.format`.

## Change log level by http request

Allows changing the log level at runtime. This package provides handler function
`ChangeLogLevel(w http.ResponseWriter, r *http.Request)`. Just add this func to your http server.

Example:
```go
package main

func main() {
    http.HandleFunc("/log", logging.ChangeLogLevel)
    http.ListenAndServe(":8080", nil)
}
```

To change the log level send a POST request with body:
```json
{
    "lvl":"<log level>",
    "packageName":"<package name>"
}
```

## Change log format by http request

Allows changing the log format at runtime, the same way the log level can be changed. This package provides handler
functions `ChangeLogFormat` and `GetLogFormat`.

```go
package main

func main() {
    http.HandleFunc("POST /api/v3/logging/format", logging.ChangeLogFormat)
    http.HandleFunc("GET /api/v3/logging/format", logging.GetLogFormat)
    http.ListenAndServe(":8080", nil)
}
```

To change the format send a POST request with body:
```json
{
    "format":"json"
}
```

```shell
$ curl -s -XGET localhost:8080/api/v3/logging/format
{"format":"text","explicit":false}

$ curl -s -XPOST localhost:8080/api/v3/logging/format -d '{"format":"json"}'
{"format":"json","explicit":true}

$ curl -s -XPOST localhost:8080/api/v3/logging/format -d '{"format":"yaml"}'
{"error":"unknown log format: yaml, expected 'text' or 'json'"}
```

The change takes effect on the next record written; no restart is needed. An unknown format value is rejected with
`400` and leaves the current format unchanged.

A format set this way is _explicit_ and survives a later configloader refresh -- an operator's deliberate switch is not
undone by a config reload. The `explicit` flag in the response reports this.

> **_NOTE:_** Like the log level endpoint, this is an operator endpoint. Place it behind the same authorization: an
> unauthenticated caller could otherwise reshape a service's log stream.

## Get all current log levels

You can get a list of all configured log levels via the following API:

```go
levels := logging.GetLogLevels()
```

The result will contain log levels for all currently created loggers, including the root log level. Loggers derived with
[`With`](#scoped-fields-with-with) are not listed, since they share their parent's level.

## Migrating to JSON

Migration happens in two independent phases. A service can adopt JSON immediately and refine its fields later, or never.

### Phase 1: flip the format, change no code

Upgrade the library, set `LOGGING_FORMAT=json`, and change nothing else. Every existing call site keeps working and
produces valid JSON:

```go
log := logging.GetLogger("orders")           // unchanged
log.InfoC(ctx, "order %d placed for %s", id, customer)
```
```json
{"time":"2026-07-30T10:15:03.123","level":"INFO","message":"order 42 placed for acme","request_id":"a1b2","tenant_id":"t-9","thread":"-","class":"orders","x_channel_request_id":"-"}
```

Note what you get for free: `request_id`, `tenant_id`, `class`, `x_channel_request_id` and any
[custom context fields](#custom-context-fields) become real JSON keys without a single call-site edit, because they come
from the context rather than from the message. For most services that is already the bulk of the value.

The trade-off is explicit: values interpolated into the message (`order 42 placed`) stay inside `message` for now. The
document is valid and ingestible; those particular values are just not yet queryable as keys.

### Phase 2: promote message values to fields

Later, file by file, replace the printf call with a `*W` call so the interpolated values become real keys:

```go
log := logging.GetFieldLogger("orders")      // one-line change per package
log.InfoWC(ctx, "order placed", "order_id", id, "customer", customer)
```
```json
{"time":"...","level":"INFO","message":"order placed","request_id":"a1b2","tenant_id":"t-9","thread":"-","class":"orders","x_channel_request_id":"-","order_id":42,"customer":"acme"}
```

The rewrite rule is mechanical: `msg` becomes the invariant text with the verbs removed, and each printf argument
becomes a key/value pair.

| Before                                       | After                                                |
| -------------------------------------------- | ---------------------------------------------------- |
| `logging.GetLogger("x")`                     | `logging.GetFieldLogger("x")`                        |
| `log.Info("started")`                        | `log.InfoW("started")`                               |
| `log.Infof("saved %d rows", n)`              | `log.InfoW("saved rows", "rows", n)`                 |
| `log.InfoC(ctx, "user %s created", id)`      | `log.InfoWC(ctx, "user created", "user_id", id)`     |
| `log.Errorf("failed for %s: %v", name, err)` | `log.ErrorW("failed", "name", name, "error", err)`   |
| `log.Warnf("retry %d/%d", attempt, max)`     | `log.WarnW("retry", "attempt", attempt, "max", max)` |

The two phases coexist in one binary and one log stream: both produce the same document shape, differing only in whether
a value sits inside `message` or beside it. A partially migrated service is also still readable in text format, where a
phase-2 call site renders as `... order placed order_id=42 customer=acme`.

## Compatibility

* `logging.Logger` is **frozen**. Its method set will not change, so downstream mocks and test doubles that implement it
  keep compiling.
* `logging.FieldLogger` is the extension point and is **not** frozen -- later minor versions may add methods to it.
  Downstream fakes should embed `logging.FieldLogger` rather than reimplementing it:

  ```go
  type myFakeLogger struct {
      logging.FieldLogger
  }
  ```
* `logging.Record` gained a `Fields` field. Unkeyed composite literals of `Record` therefore no longer compile; use
  keyed literals (`logging.Record{Message: ...}`), which `go vet` recommends anyway for structs from other packages.
* The default format is `text`, so upgrading the library does not change a service's output on its own.
