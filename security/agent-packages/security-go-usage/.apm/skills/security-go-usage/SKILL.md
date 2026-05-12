---
name: security-go-usage
description: Use when handling service-to-service authentication in a Qubership Go microservice on Kubernetes — attaching K8s service-account tokens to outbound calls or verifying inbound JWTs via OIDC.
---

# qubership-core-lib-go security

Helper skill for the `security` package from `github.com/netcracker/qubership-core-lib-go/v3`. The package covers two complementary flows:

- **Outbound** — getting a fresh Kubernetes service account token to attach to requests you send (`security/tokensource`).
- **Inbound** — verifying tokens that other services attach to requests they send to you (`security/tokenverifier`), plus claim helpers in `security/token`.

Both flows are designed for Kubernetes projected service-account tokens and OIDC-based verification through the Kubernetes API server.

## Sub-packages at a glance

| Sub-package                     | Purpose                                                      |
|---------------------------------|--------------------------------------------------------------|
| `security/tokensource`          | Fetch & auto-refresh K8s SA tokens (default + audience-bound)|
| `security/tokenverifier`        | Verify incoming JWTs via OIDC (Kubernetes issuer)            |
| `security/token`                | Extract standard JWT and Kubernetes claims                   |
| `security/oidc`                 | Lower-level OIDC client (rarely used directly)               |

## Outbound: attaching tokens to your requests (`tokensource`)

The package automatically watches the token file via `fsnotify` and refreshes the in-memory cache when Kubernetes rotates the token. Your job: **call `Get…Token` on every request and never store the result**.

### Default service account token

Mounted by Kubernetes at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

```go
import "github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"

token, err := tokensource.GetServiceAccountToken(ctx)
if err != nil {
    return fmt.Errorf("get SA token: %w", err)
}
req.Header.Set("Authorization", "Bearer "+token)
```

### Audience-specific token (projected volume)

Mounted by Kubernetes at `/var/run/secrets/tokens/<audience>/token`. Used for service-to-service auth where the receiver expects a specific audience claim.

```go
import "github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"

token, err := tokensource.GetAudienceToken(ctx, tokensource.AudienceDBaaS)
```

Predefined audiences exported by the package:

| Constant                | Value         |
|-------------------------|---------------|
| `AudienceNetcracker`    | `netcracker`  |
| `AudienceDBaaS`         | `dbaas`       |
| `AudienceMaaS`          | `maas`        |

You can pass an arbitrary string for custom audiences. The audience name **must** match the `audience` field in the Kubernetes projected volume spec — otherwise the file simply won't exist and you get a "token with audience X was not found" error.

### Pod manifest reminder

For audience tokens, the deployment must include a projected service-account volume:

```yaml
volumes:
  - name: dbaas-token
    projected:
      sources:
        - serviceAccountToken:
            path: dbaas/token
            audience: dbaas
            expirationSeconds: 3600
volumeMounts:
  - name: dbaas-token
    mountPath: /var/run/secrets/tokens
    readOnly: true
```

If the deployment is missing this, no amount of code changes will help — flag it explicitly when reviewing.

### Custom token directories (testing only)

```go
tokensource.DefaultServiceAccountDir = "/custom/serviceaccount"
tokensource.DefaultAudienceTokensDir = "/custom/tokens"
```

Override these **before** the first `Get…Token` call (i.e. at startup or in tests). The watcher is initialized lazily on first use; changing the directory afterwards has no effect.

## Inbound: verifying incoming tokens (`tokenverifier`)

The verifier discovers the OIDC provider (the Kubernetes API server), fetches JWKS, validates signature + audience + expiration, and returns a parsed `*jwt.Token`. It uses a secure HTTP transport that auto-attaches the local SA token for OIDC calls, plus exponential-backoff retry on transient 5xx/network errors.

### Construction (do this once at startup)

```go
import "github.com/netcracker/qubership-core-lib-go/v3/security/tokenverifier"

// audience must match the audience the caller used when requesting their token
verifier, err := tokenverifier.NewKubernetesVerifier(ctx, "my-service")
if err != nil {
    log.Fatalf("create verifier: %v", err)
}
```

`NewKubernetesVerifier` blocks on first call to do OIDC discovery. Don't create one per request — keep it as a package-level dependency.

For tighter control over JWKS refresh cadence and unknown-KID rate limiting use `NewKubernetesVerifierOverride` with a custom `Override{RefreshInterval, RefreshUnknownKID}`. The defaults (24h refresh, 1 unknown-KID lookup per 5 min) are fine for almost everyone — only change them with a concrete reason.

### Verifying

```go
parsed, err := verifier.Verify(ctx, rawToken)
if err != nil {
    // expired, bad signature, wrong audience, malformed — treat as 401
    return http.StatusUnauthorized
}
```

### Custom validations

`NewKubernetesVerifier` accepts variadic `Validation func(*jwt.Token) error` callbacks that run after signature/audience/expiry checks. Use them to enforce domain-specific rules (subject allow-list, namespace allow-list, etc.):

```go
import (
    "github.com/golang-jwt/jwt/v5"
    qtoken "github.com/netcracker/qubership-core-lib-go/v3/security/token"
)

func requireNamespace(allowed map[string]bool) tokenverifier.Validation {
    return func(t *jwt.Token) error {
        ns, err := qtoken.GetNamespace(t)
        if err != nil { return err }
        if !allowed[ns] { return fmt.Errorf("namespace %q not allowed", ns) }
        return nil
    }
}

verifier, err := tokenverifier.NewKubernetesVerifier(ctx, "my-service",
    requireNamespace(map[string]bool{"prod": true, "stage": true}))
```

`ValidateIssuedAt` is appended automatically — you don't need to add it.

## Reading claims (`security/token`)

After `Verify` succeeds you have a `*jwt.Token`. Use the helpers instead of poking at `Claims` manually — they handle missing / wrongly-typed claims uniformly.

**Standard JWT claims:**

```go
import qtoken "github.com/netcracker/qubership-core-lib-go/v3/security/token"

iss, _ := qtoken.GetIssuer(jwt)
sub, _ := qtoken.GetSubject(jwt)
aud, _ := qtoken.GetAudience(jwt)        // jwt.ClaimStrings
exp, _ := qtoken.GetExpirationTime(jwt)  // *jwt.NumericDate
iat, _ := qtoken.GetIssuedAt(jwt)
nbf, _ := qtoken.GetNotBefore(jwt)
jti, _ := qtoken.GetId(jwt)
```

**Kubernetes claims** (from the `kubernetes.io` claim group):

```go
ns, _   := qtoken.GetNamespace(jwt)
sa, _   := qtoken.GetServiceAccountName(jwt)
saUID   := qtoken.GetServiceAccountId(jwt)
```

**Generic accessors** for arbitrary claims:

```go
val, _ := qtoken.GetStringValue(jwt, "custom-claim")
m, _   := qtoken.GetMapValue(jwt, "kubernetes.io")
ns, _  := qtoken.StringValue(m, "namespace")
```

## Wiring `Verify` into request handling

Read the bearer token from `Authorization` header (`net/http`, Fiber) or `authorization` metadata key (gRPC), strip the `Bearer ` prefix, then:

```go
jwt, err := verifier.Verify(r.Context(), raw)
if err != nil {
    // expired, bad signature, wrong audience, malformed — treat as 401 / Unauthenticated
}
```

Stash the parsed `*jwt.Token` on the request context (`context.WithValue(r.Context(), claimsKey{}, jwt)` for `net/http`, `c.Locals(claimsKey{}, jwt)` for Fiber) so handlers can read claims via `security/token` helpers.

## Service-to-service: combining both packages

```go
// caller: attach your own SA token
token, _ := tokensource.GetServiceAccountToken(ctx)
req.Header.Set("Authorization", "Bearer "+token)

// callee: verify the incoming token
parsed, err := verifier.Verify(ctx, rawFromHeader)
```

If the callee enforces a specific audience, the caller must use `GetAudienceToken(ctx, "<that-audience>")` instead of the default SA token, and the deployment must mount the matching projected volume.

## Common pitfalls

- **Storing the token in a package-level variable** — it goes stale after Kubernetes rotates it. Always call `Get…Token` per request.
- **Creating the verifier per-request** — first call does OIDC discovery (network round-trips). Build it once at startup, reuse.
- **Audience mismatch** — `NewKubernetesVerifier(ctx, "X")` validates the JWT `aud` claim equals `X`. The caller's token `aud` must match exactly. Misalignment between deployment YAML and code is the #1 cause of `audience mismatch` errors.
- **Asking for an audience token without the projected volume** — code looks fine, runtime fails with "token with audience X was not found". Check the pod spec.
- **Overriding `DefaultServiceAccountDir` / `DefaultAudienceTokensDir` after the first call** — the watcher is already initialized against the old path. Set these at startup only, ideally only in tests.
- **Logging tokens** — never log full tokens. Truncate to the first ~20 chars at most, even in debug.
- **Skipping `context`** — pass the request context to `Verify` so cancellation and deadlines propagate; don't substitute `context.Background()`.
- **Long-running goroutines holding a token** — re-fetch from `tokensource` at the start of each iteration; the in-memory cache makes this cheap.
- **Custom validations expecting non-nil claims** — claims may be missing. Use the `security/token` helpers (they return errors) rather than direct map access that panics.
