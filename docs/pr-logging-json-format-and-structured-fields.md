# PR description — JSON log format and structured fields

Suggested title (conventional commits):

```
feat(logging): add JSON log format and slog-style structured fields
```

---

## Summary

Adds a JSON output format and a `log/slog`-style structured-field API to the `logging` package, selectable by
configuration and switchable at runtime over HTTP.

Existing text output is **byte-for-byte unchanged** and the exported `logging.Logger` interface is **unchanged**, so
this is a drop-in upgrade: no consumer has to modify a single line to keep working, and none has to modify a single line
to start emitting JSON.

Design and rationale: [`docs/plans/2026-07-30-logging-json-format-and-structured-fields.md`](plans/2026-07-30-logging-json-format-and-structured-fields.md).

## Motivation

The package emitted exactly one format — a fixed 7-bracket text pattern — and had no way to select another. The only
mechanism for extra fields was `SetCustomLogFields("%{a} %{b}")`, a template resolved solely from `context.Context` by
string key, re-compiled with `regexp.Compile` on **every record**, and prepended to the message text. Anything a caller
wanted to log alongside a message had to be interpolated into the message string, where it is not queryable.

We want logs ingestible as structured documents, and we want the migration to be mechanical enough to automate with
agents/skills.

## What changed

### JSON format

New `logging/json_format.go`. Hand-rolled, no new dependencies, `sync.Pool`-backed buffers, no reflection on the hot
path.

```json
{"time":"2026-07-30T10:15:03.123","level":"INFO","message":"order placed","request_id":"a1b2","tenant_id":"t-9","thread":"-","class":"orders","x_channel_request_id":"-","order_id":42}
```

Same key set as the text format so queries translate mechanically. Key **order** differs deliberately: `time`, `level`
and `message` lead so a raw line is readable in a terminal without `jq`. Absent values are `"-"`, not `null`, matching
the text format's existing contract.

### Format selection

Property `logging.format` / env `LOGGING_FORMAT`, values `text` (default) or `json`, resolved through the same
two-phase configloader/env lookup as the log level and re-read on configloader init/refresh.

### Runtime switching over HTTP

New `ChangeLogFormat` and `GetLogFormat` handlers, mirroring the existing `ChangeLogLevel`:

```
POST /api/v3/logging/format {"format":"json"} -> 200 {"format":"json","explicit":true}
POST /api/v3/logging/format {"format":"yaml"} -> 400 {"error":"unknown log format: yaml, expected 'text' or 'json'"}
GET  /api/v3/logging/format                   -> 200 {"format":"json","explicit":true}
```

Two deliberate decisions here:

- An unknown value returns **400 rather than silently falling back to text**. Silent fallback is right for configuration
  bootstrap (a typo must not fail a service start); it is wrong for an explicit operator API, where answering 200 while
  leaving the format unchanged would hide the mistake.
- A format set over HTTP or in code is marked *explicit* and **survives a later configloader refresh**, so an operator's
  deliberate switch is not silently reverted by a config reload. `GET` reports this via the `explicit` flag.

### Structured fields

New `logging/fields.go` and `logging/field_logger.go`.

```go
log := logging.GetFieldLogger("orders")

log.InfoWC(ctx, "order placed", "order_id", 42, "customer", "acme")

scoped := log.With("component", "checkout")
scoped.WarnW("retrying", "attempt", 2)
```

`msg` is a **literal** — never passed through `fmt.Sprintf`, so it may contain `%` freely. A malformed argument list
never panics and never drops data; the offending value is logged under `!BADKEY`.

In text format fields render logfmt-style after the message (`... order placed order_id=42 customer=acme`); in JSON they
become top-level keys.

`With` returns a *view* of the underlying logger, not a copy: level, format, output and the write mutex stay shared, so
a level refresh or an HTTP level change reaches derived loggers. They are not registered, so they do not pollute
`GetLogLevels()`.

### Configurable output

`logging.SetOutput(w)` globally and `SetOutput` per logger, replacing 15 hardcoded `os.Stdout` call sites. Resolved
lazily at write time, so reassigning `os.Stdout` still works.

### Bug fixes bundled

| Fix | Impact |
|---|---|
| `regexp.Compile` hoisted out of the per-record path | ~30 of the 33 allocations of every log line |
| `strings.TrimLeft(field, "%{")` cutset bug | field names starting with `%` or `{` were mangled |
| Unreachable second `panic` in `Panicf` | dead code / Sonar smell |
| `logFormat`/`globalLogFormat` written without synchronisation while being read | pre-existing data race; now `atomic.Pointer` |
| `SetCustomLogFields` stored write-only dead state on the instance | template now parsed once and stored where the formatter actually reads it |

## Backward compatibility

- **`logging.Logger` is frozen.** All new capability lives on `FieldLogger`, which embeds it. Downstream mocks and test
  doubles implementing `logging.Logger` keep compiling. `TestLoggerInterface_UnchangedMethodSet` asserts the original
  15-method set by reflection so a future change cannot break this silently.
- **Text output is byte-identical.** Pinned by golden tests written against the pre-change code and passing unmodified
  afterwards, covering nil/populated context, `GetLogValue` objects, unsupported value types, `caller`, all five levels,
  custom templates, and an installed custom message format.
- **`GetLogger` is unchanged** and still returns `Logger`. `GetFieldLogger` returns the *same* logger object, typed as
  `FieldLogger`. `Fields(l)` adapts any `Logger`, falling back to a message-folding adapter for foreign
  implementations rather than panicking.
- **Default format is `text`**, so upgrading the library does not change any service's output on its own.

The one theoretical source break: `logging.Record` gained a `Fields` field, so **unkeyed** composite literals of
`Record` no longer compile. All in-repo literals are keyed, and `go vet`'s `composites` check already flags unkeyed
literals of imported structs.

## Performance

The text path got **faster while staying byte-identical**. `benchstat`, 10 runs each, baseline captured against
unmodified code before any production change:

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `DefaultFormat_NilCtx` | −68.3% | −83.4% | 33 → 11 |
| `DefaultFormat_Ctx3Values` | −65.7% | −79.8% | 37 → 15 |
| `DefaultFormat_CustomFields0` | −66.8% | −79.8% | 37 → 15 |
| `DefaultFormat_CustomFields3` | −40.8% | −60.9% | 48 → 26 |
| `AssembleCustomLogFields` | −57.9% | −77.6% | 32 → 10 |
| `Logger_InfoC_Discard` | −52.0% | −64.6% | 44 → 22 |
| `Logger_Parallel` | −55.5% | −64.6% | 44 → 22 |
| `Logger_Disabled` | ~ | 0 | 0 |

Geomean **−46.7% time, −61.4% allocations**. The dominant cause was the per-record `regexp.Compile`, which ran even
when no custom-fields template was configured.

New code: `JSONFormat_NilCtx` 678 ns / 3 allocs (cheaper than the text formatter's 782 ns / 11);
`JSONFormat_With4Fields` 1068 ns / 7 vs `TextFormat_With4Fields` 1471 ns / 20; format resolution 1.45 ns / 0 allocs;
`argsToFields(nil)` 1.94 ns / 0 allocs; every JSON encoder arm 0 allocs except the `fmt.Sprint` fallback.

## Tests

114 tests and 28 benchmarks in the package. Notable coverage:

- **Compatibility:** full-line golden assertions (`assert.Equal`, not `Contains`), a byte-identity matrix, and the
  frozen-interface reflection test.
- **Phase-1 migration gate:** a table over all 15 legacy methods asserting each emits a well-formed JSON document with a
  correctly printf-formatted `message` and the full key set.
- **JSON encoding:** escaping table covering quotes, backslashes, all control characters, `U+2028`/`U+2029`, emoji,
  invalid UTF-8, a 64 KiB string and a JSON-injection attempt — every case must `json.Unmarshal` cleanly; value-type
  table covering every arm of the type switch including `NaN`/`±Inf`.
- **Pool safety:** 200 concurrent goroutines with distinct messages, plus an explicit test that a returned slice is not
  mutated by a later `format()` call.
- **Field aliasing:** sibling loggers derived from one parent must not share a backing array — both at the
  `concatFields` level and end-to-end.
- **Concurrency under `-race`:** format swapping while writers log, HTTP handler called concurrently with logging,
  concurrent `With` children.

### Test-isolation harness

The package's tests were process-global-state minefields that leaked into each other — one carried a
`// have to clear message logFormat or other test won't pass` comment admitting it. Added
`logging/testhelpers_test.go` with snapshot/restore of every mutable global, `t.Setenv` in place of
`os.Setenv`/`os.Clearenv`, and non-registering test loggers.

**The package now passes under `go test -shuffle` for any seed; before this change it failed on most seeds.** Two
pre-existing `go vet` failures in `logger_test.go` (unused `Lvl.String()` result, `copylocks` on `createTestLogger`)
are also fixed, so `go vet ./logging/` is clean.

## Documentation

`logging/README.md` rewritten. It was stale and actively misleading — it documented a `logging.SetFormat` that has never
existed, a 3-field format pattern that does not match the code, per-level console colours that are not emitted, and two
examples using `r.Ctx.requestId` that do not compile. All fixed, with sample outputs taken from the golden tests so they
cannot drift again.

New sections: log format (text/json), runtime format switching, structured fields, custom context fields, output
destination, compatibility, and a two-phase migration guide.

## Migration

Two independent phases; they coexist in one binary and one log stream.

**Phase 1 — flip the format, change no code.** Set `LOGGING_FORMAT=json` and every existing call site emits valid JSON.
`request_id`, `tenant_id`, `class`, `x_channel_request_id` and any custom context fields become real keys for free,
because they come from the context rather than the message. Values interpolated into the message stay inside `message`
for now.

**Phase 2 — promote message values to fields**, per call site, whenever convenient:

| Before | After |
|---|---|
| `logging.GetLogger("x")` | `logging.GetFieldLogger("x")` |
| `log.Infof("saved %d rows", n)` | `log.InfoW("saved rows", "rows", n)` |
| `log.InfoC(ctx, "user %s created", id)` | `log.InfoWC(ctx, "user created", "user_id", id)` |
| `log.Errorf("failed for %s: %v", name, err)` | `log.ErrorW("failed", "name", name, "error", err)` |

The rewrite rule is mechanical, which is what makes it automatable.

## Verification performed

```bash
go vet ./... && go build ./...
go test -race ./logging/ ./context-propagation/... ./security/... ./serviceloader/...
go test -count=1 -shuffle=<seed> ./logging/          # green for every seed tried
benchstat baseline.txt after.txt

# Phase-1 gate: unmodified consumers emit valid JSON with zero code changes
LOGGING_FORMAT=json go test -v ./context-propagation/... | grep -E '^\{' | jq -e .
```

Also ran a scratch binary under both formats, exercising the HTTP switch: the change takes effect on the next record
with no restart, and a rejected `{"format":"yaml"}` leaves the active format untouched.

## Not addressed (pre-existing, unrelated)

- `TestLazy_Get_Concurrent` (`utils/lazy.go:95`) races under `-race`; reproduces on a clean tree.
- Three files fail `gofmt` on a clean tree: `context-propagation/baseproviders/tenant/{tenant_context_object,tenant_provider}.go`
  and `security/rest/client_test.go`.

## Review checklist

- [ ] Key names and `"-"` placeholder convention match what our log ingestion expects
- [ ] `logging.format` / `LOGGING_FORMAT` naming is consistent with platform conventions
- [ ] Suggested endpoint paths (`/api/v3/logging/format`) match the platform's admin API layout
- [ ] Confirm the format endpoints will be mounted behind the same authorization as the log level endpoint
- [ ] Release notes mention the `Record` unkeyed-literal caveat and that `FieldLogger` is not frozen
