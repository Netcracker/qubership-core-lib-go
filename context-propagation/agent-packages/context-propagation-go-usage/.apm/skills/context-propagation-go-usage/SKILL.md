---
name: context-propagation-go-usage
description: Use this skill to propagate request context when handling incoming and outgoing requests in Go code.
---

# qubership-core-lib-go context-propagation

Helper skill for the `context-propagation` package from `github.com/netcracker/qubership-core-lib-go/v3`. The library propagates request-scoped data (headers, IDs) between microservices via Go's `context.Context`.

## Core packages

- `context-propagation/ctxmanager` — register providers, init/read context, snapshots
- `context-propagation/ctxhelper` — copy context data into outgoing requests/responses
- `context-propagation/baseproviders/...` — ready-to-use providers per header

## Setup checklist (do these in order)

1. **Register providers once at startup** (not thread-safe — never register concurrently with reads):

   ```go
   import (
       "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
       "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders"
   )

   ctxmanager.Register(baseproviders.Get())
   ```

   `baseproviders.Get()` returns: `AcceptLanguage`, `XVersion`, `XVersionName`, `ApiVersion`, `XRequestId`, `AllowedHeader`, `BusinessProcess`, `OriginatingBiId`, `ClientIp`.

2. **Add a middleware** that calls `ctxmanager.InitContext(ctx, headers)` on every request. Headers must be `map[string]interface{}`.

   **net/http:**

   ```go
   func contextPropagationMiddleware(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           headers := map[string]interface{}{}
           for k := range r.Header {
               headers[k] = r.Header.Get(k)
           }
           r2 := r.WithContext(ctxmanager.InitContext(r.Context(), headers))
           next.ServeHTTP(w, r2)
       })
   }
   ```

   **Fiber:**

   ```go
   app.Use(func(c *fiber.Ctx) error {
       headers := map[string]interface{}{}
       c.Request().Header.VisitAll(func(k, v []byte) { headers[string(k)] = string(v) })
       c.SetUserContext(ctxmanager.InitContext(c.UserContext(), headers))
       return c.Next()
   })
   ```

3. **For `AllowedHeader`**, set `HEADERS_ALLOWED` env var or `headers.allowed=h1,h2,...` property; `configloader.Init` must be called in `main`.

## Reading values from context

Each base provider exposes an `Of(ctx)` (or `Get(ctx)`) helper returning a typed object:

```go
import "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"

obj, err := xrequestid.Of(ctx)
id := obj.GetRequestId()
```

| Provider            | Package                        | Accessor   |
|---------------------|--------------------------------|------------|
| Accept-Language     | `baseproviders/acceptlanguage` | `Of(ctx)`  |
| Allowed headers     | `baseproviders/allowedheaders` | `Of(ctx)`  |
| API version         | `baseproviders/apiversion`     | `Of(ctx)`  |
| X-Request-Id        | `baseproviders/xrequestid`     | `Of(ctx)`  |
| X-Version           | `baseproviders/xversion`       | `Of(ctx)`  |
| X-Version-Name      | `baseproviders/xversionname`   | `Get(ctx)` |
| Business-Process-Id | `baseproviders/businessprocess`| `Of(ctx)`  |
| Originating-Bi-Id   | `baseproviders/originatingbiid`| `Of(ctx)`  |
| X-Nc-Client-Ip      | `baseproviders/clientip`       | `Of(ctx)`  |

**Generic alternative:**

```go
obj, err := ctxmanager.GetContextData(ctx, xrequestid.X_REQUEST_ID_COTEXT_NAME)
typed := obj.(xrequestid.XRequestIdContextObject)
```

**Notes:**
- `X-Request-Id` is auto-generated when missing.
- `apiversion` falls back to `v1` when the URL has no version.
- `clientip` resolves from the first IP of `X-Forwarded-For`, then `X-Nc-Client-Ip`; otherwise no propagation.
- `BusinessProcess` / `OriginatingBiId` skip propagation when empty/unset.

## Setting values explicitly

```go
ctx, err := ctxmanager.SetContextObject(ctx, originatingbiid.ORIGINATING_BI_ID_CONTEXT_NAME,
    originatingbiid.NewOriginatingBiIdContextObject("some-value"))
```

## Propagating to outgoing requests / responses

Use `ctxhelper`, not manual header copying:

```go
import "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxhelper"

// outgoing HTTP request — copies SerializableContext data
req, _ := http.NewRequest("GET", url, nil)
_ = ctxhelper.AddSerializableContextData(ctx, req.Header.Add)

// HTTP response — copies ResponsePropagatableContext data
_ = ctxhelper.AddResponsePropagatableContextData(ctx, w.Header().Add)
```

**Other helpers:**
- `ctxmanager.GetSerializableContextData(ctx) map[string]string`
- `ctxmanager.GetResponsePropagatableContextData(ctx) map[string]string`
- `ctxmanager.GetSerializableHeaders(ctx) []string` — header names that will propagate

## Custom provider

Create one only when you need to propagate a header not covered by `baseproviders`.
See `baseproviders/xrequestid/x_request_id_provider.go` as a reference: implement
`ContextProvider` (`InitLevel`, `ContextName`, `Provide`, `Set`, `Get`) plus a
context object with `Serialize()`, then register via `ctxmanager.RegisterSingle()`.

## Snapshots

Use only when you start a goroutine that outlives the request and need the request
context inside it (passing `ctx` directly would tie the goroutine to request
cancellation). Capture in the handler, activate inside the goroutine:

```go
snap := ctxmanager.CreateFullContextSnapshot(ctx)
go func() {
    newCtx, _ := ctxmanager.ActivateContextSnapshot(snap)
    // use newCtx
}()
```

## Common pitfalls

- Calling `ctxmanager.Register` after the server starts handling requests — register at startup only.
- `Of(ctx)` returns `"context doesn't contain ..."` — wire the `InitContext` middleware before any handler that reads context.
- Headers map passed to `InitContext` must be `map[string]interface{}` (not `map[string]string`).
- `AllowedHeader` requires `configloader.Init` plus `headers.allowed` / `HEADERS_ALLOWED` to be set; without them it silently does nothing.
- Outgoing requests don't propagate automatically — call `ctxhelper.AddSerializableContextData`.
