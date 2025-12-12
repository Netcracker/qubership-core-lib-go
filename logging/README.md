# Logger

This package is indented for logging. It provides different log levels, ability to customize logs' format and to 
change log level during runtime.

- [Install](#install)
- [Setup logger](#setup-logger)  
- [Log levels](#log-levels)
  * [Log with context](#log-with-context)
- [Log level settings](#log-level-settings)
  * [Bootstrap phase configuration](#bootstrap-phase-configuration)
  * [Runtime phase configuration](#runtime-phase-configuration)  
  * [How to define log level](#how-to-define-log-levels)
- [Default Formatting](#default-formatting)
- [Custom Formatting](#custom-formatting)
- [Custom Formatting per logger](#custom-formatting-per-logger)
- [Change log level by http request](#change-log-level-by-http-request)
- [Get all current log levels](#get-all-current-log-levels)


## Install 

To install `logger` use
```go
 go get github.com/netcracker/qubership-core-lib-go/v3@<latest released version>
```

## Setup logger

To get logger user should use func `GetLogger` and pass correct package name as a parameter. User may create logger at _init_ function.

For example, logger to log everything located in dbaas package looks like:
```Go
package main

var logger logging.Logger

func init() {
	logger = logging.GetLogger("dbaas")
}
```

**Note:** It is highly recommended using this package with [configloader package](../configloader/README.md),
because configloader allows configuring logging process with application.yaml file. It means that your `main` function should call the code:
```go
  configloader.Init(configloader.BasePropertySource())
```


## Log levels

The logger interface defines 5 levels of logging: `Debug`, `Info`, `Warn`, `Error` and `Panic`. 
These will accept a variadic strings. 

Additionally, each of the log levels offers a formatted string as well: `Debugf`, `Infof`, `Warnf`, `Errorf` and `Panicf`. 
These functions are like fmt.Printf and offer the ability to define a format string and parameters to populate it.

_Note, that all logger messages with Panic level at first will log critical event and then create a panic with message from logger._

Examples:
```Go
    log := logging.GetLogger("main")
    log.Info("This is info string")
    log.Infof("This is %i string with %d parameter", 2, 7.2)
    log.Errorf("This is error string with %s parameter", "parameter")
    log.Panic("This logg will create panic with this message")
```

Note: each level has its own color during printing to console. More info at [Formatting](#default-formatting)

### Log with context

For each log level there is a possibility to log a message with a context (it should be context.Context): `DebugC`, `InfoC`, `WarnC`, `ErrorC` and `PanicC`.
Information about context will be added to log output in accordance with the specified format.   
If you want to add information about tenantId and requestId to output, you have to override default message format. See [Custom Formatting](#custom-formatting) section for more info.

```Go
    logging.DebugC(ctx,"teststring %s, %s", "one" "two")
```

## Log Level Settings

Please, read this section very attentively in case not to have problems with logging. 

Logger has two phases: `logger's bootstrap time` and `logger's runtime`. The main difference between them is the different process of configurations loading.
Logger usually gets configuration from configloader, but there are no properties during logger's bootstrap time because configloader is not initialized yet. 
Logger's bootstrap time ends when `configloader is initialized`.

**Default level for all phases is INFO.** If you want to use default level, don't provide any properties at all.

### Bootstrap phase configuration

During logger's bootstrap phase you may use default level or configure log level with environment. You may configure global log level with variable `LOGGING_LEVEL_ROOT`
or configure level for specific package with variable `LOGGING_LEVEL_<package_name>`

Example: how to set global `warn` lvl and `debug` lvl  for `dbaas` package during bootstrap phase.
```properties
    LOGGING_LEVEL_ROOT=warn
    LOGGING_LEVEL_DBAAS=debug
```
### Runtime phase configuration

During logger's runtime phase you may use default level or configure level with application.yaml or with environment variables.
 
To override default level and set new level for all packages use property `logging.level.root` with application.yaml or environment variable `LOGGING_LEVEL_ROOT`. 

> **_NOTE:_**  You can configure logger through `application.yaml` and `environment` if you provide and initialize configloader with these property sources.  
> For example `configloader.Init(configloader.BasePropertySource())`. Pay attention that you have to call configloader#Init method only and in your main function as early as possible. 

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

Also, it is possible to set log level for specific package. You may do it with property `logging.level` with application.yaml or 
with environment variables `LOGGING_LEVEL_<package-name>`.

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

**Note** that package level will override global level. So in below example all packages except dbaas will have `warn` level, and dbaas will have `debug` level.
```yaml
  logging.level.root: warn
  logging.level:
      dbaas: debug
```

### How to define log levels 

You may use any case: low or upper. If level value is incorrect, logger will use default level.

|Desired log level   | Property value  |
|--------------------|-----------------|
| Panic              | fatal           |
| Error              | error           |
| Warn               | warn            |
| Info               | info            |
| Debug              | debug           |

## Default Formatting

There is a default format for logging with message about log level. Default message format looks like 
`[timestamp] [LOG LEVEL] [caller=<package name>] log string`.

For example for log with _INFO_ log level, located in _main_ package and with text _"Info in main"_ output will be:
```go
  [2021-05-07 14:42:34.809] [INFO] [caller=main] Info in main
```

## Custom Formatting

If default format isn't suitable, there is a possibility to create user's own format function. User should use `SetLogFormat(format func(r *Record) []byte)` 
and pass new format function as a parameter.

Example: such formatting will produce logs in this format and every log message will be light green coloured.
```go
package main

import (
  "bytes"
  "fmt"
  "github.com/netcracker/qubership-core-lib-go/v3/configloader"
  "github.com/netcracker/qubership-core-lib-go/v3/logging"
  "strings"
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
  logging.SetFormat(customLogFormat)
  log.Info("log string")
}
```
Output is:

```go
    [2021-05-07] [INFO] [packageName=main] log string
```

Also, user can set only new message format. It may be useful when user needs information about tenantId or requestId in log messages. 
To set new message format use func `SetMessageFormat`.

Below example will produce log with new message format, where filed with requestId will be added.

```go
package main

import (
  "bytes"
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
    r.Ctx.requestId,
    "main",
    r.Message,
  )
}

func init() {
  configloader.InitWithSourcesArray(configloader.BasePropertySources())
  log := logging.GetLogger("main")
}

func main() {
  logging.DefaultFormat.SetMessageFormat(customMessageFormat)
  log.InfoC(ctx, "Log with request id")
}
```

Output is

```go
    [2021-05-07] [INFO] [requestId=123] [packageName=main] Log with request id
```

## Custom Formatting per logger

If you need a different format depending on the logger, there is a possibility to create user's own format function for
a particular logger. User should use `SetLogFormat(format func(r *Record) []byte)` and pass new format function as a
parameter to logger.
Example: such formatting will produce logs in this format and every log message for the "custom" logger will be light
green coloured.
```go
package main

import (
  "bytes"
  "fmt"
  "github.com/netcracker/qubership-core-lib-go/v3/configloader"
  "github.com/netcracker/qubership-core-lib-go/v3/logging"
  "strings"
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
    "main",
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

```go
    [2021-05-07 14:42:34.809] [INFO] [packageName=main] mainLog string
    [2021-05-07] [INFO] [packageName=main] customLog string
```

Also, user can set only new message format. It may be useful when user needs information about tenantId or requestId in log messages.
To set new message format use func `SetMessageFormat`.

Below example will produce log with new message format, where filed with requestId will be added.

```go
package main

import (
  "bytes"
  "fmt"
  "github.com/netcracker/qubership-core-lib-go/v3/configloader"
  "github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var mainLog logging.Logger
var customLog logging.Logger

func customMessageFormat(r *logging.Record, b *bytes.Buffer, color int, lvl string) (int, error) {
  TimeFormat := "2006-01-02"
  return fmt.Fprintf(b, "[%s] \x1b[%dm[%s]\x1b[0m [requestId=%s] [caller=%s] %s",
    r.Time.Format(TimeFormat),
    color,
    lvl,
    r.Ctx.requestId,
    "main",
    r.Message,
  )
}

func init() {
  configloader.InitWithSourcesArray(configloader.BasePropertySources())
  mainLog = logging.GetLogger("main")
  customLog = logging.GetLogger("custom")
}

func main() {
  customLog.SetMessageFormat(customMessageFormat)
  mainLog.InfoC(ctx, "mainLog string")
  customLog.InfoC(ctx, "Log with request id")
}
```

Output is

```go
    [2021-05-07 14:42:34.809] [INFO] [packageName=main] mainLog string
    [2021-05-07] [INFO] [requestId=123] [packageName=main] Log with request id
```

## Change log level by http request

Allows changing log level in runtime. This package provides handler function `ChangeLogLevel(w http.ResponseWriter, r *http.Request)`.
Just add this func to your http server.

Example:
```go
package main

func main() {
    http.HandleFunc("/log", logging.ChangeLogLevel)
    http.ListenAndServe(":8080", nil)
}
```

To change log level user should send POST request with body:
```json
{
    "lvl":"<log level>",
    "packageName":"<package name>"
}
```

## Get all current log levels

You can get list of all configured log levels via following API:

```go
levels := logging.GetLogLevels()
```

The result will contain log levels for all currently created loggers, including root log level.