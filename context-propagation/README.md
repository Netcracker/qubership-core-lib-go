# Context propagation

`Context-propagation` framework is intended for propagating some value from one microservice to another.
Additionally, the package allows to store custom request data and get them where you want.  

Also, the framework contains some useful methods for working with context such as
create a snapshot and activate it sometime later. Also, you can create own contexts for propagating your data or
override existed for customization for your needs.

* [Install](#install)
* [Context-propagation](#context-propagation)
* [Context Manager](#context-manager-ctxmanager)
* [Context helper](#context-helperctxhelper)  
* [Base contexts](#base-contexts)
* [How to write own context](#how-to-write-own-context)
* [How to override existed context](#how-to-override-existed-context)
* [Context snapshots](#context-snapshots)

## Install

To install `context-propagation` use
```go
 go get github.com/netcracker/qubership-core-lib-go/v3@<latest released version>
```

# Context propagation

The package allows to register and fill request context on base request data (REST & messaging). We can also use this package to propagate resquest data from microservice to microservice.

This package uses request scope `context.Context` to store data from requests.

## How to use

**At first,** you have to register `providers`.


```go
    import (
        "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
    )
    ctxmanager.Register([]ContextProviders)
```

You can get base context `providers` by method
``go
 baseproviders.Get()
``


This method provides the following contexts:
```
AcceptLanguage
XVersion
XVersionName
ApiVersion
XRequestId
AllowedHeader
BusinessProcess
OriginatingBiId
ClientIp
XChannelRequestId
```

**Secondly,** on each request you should init context by calling the method `ctxmanager.InitContext(ctx, map[string][]string)` and passing `context.Context` and request data.

For example if you use fiber framework then you may create middleware something like that:
```go
    import (
        "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
    )

    app := fiber.New()
    
    app.Use(func(c *fiber.Ctx) error {
        requestHeaders := map[string]interface{}{}
        c.Request().Header.VisitAll(func(key, value []byte) {
        requestHeaders[string(key)] = string(value)
        })
        
        var ctx = c.UserContext()
        ctx = ctxmanager.InitContext(ctx, requestHeaders)
        
        c.SetUserContext(ctx)
        return c.Next()
	})
```
If native http middleware then something like that:
```go
import (
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)



func contextPropagationMiddleware(next http.Handler) http.Handler{
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){
        requestHeaders := map[string]interface{}{}
        for key, _ := range r.Header{
            requestHeaders[key] = r.Header.Get(key)
        }
        
        r2 := r.WithContext(ctxmanager.InitContext(r.Context(), requestHeaders))
        next.ServeHTTP(w, r2)
    })
}

router := mux.NewRouter()

router.Use(contextPropagationMiddleware) 

)
```


**Thirdly,** to get propagatable context from `context.Context` use 
```go
import (
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
ctxmanager.GetSerializableContextData(ctx)
```

# Context Manager (ctxmanager)

Context manager is central class which helps to interact with contexts. 

Context manager contains interface `ContextProvider`. `ContextProvider` allow to set, get and create `context object`. Also, can provide data from requests to `context object`.
For more information click [here](./ctxmanager/context_manager.go#L18)

`Context object` is a view of data from requests.You can find example [below](#how-to-write-own-context).
Or look at base contexts [here](./baseproviders).

Context manager have functions to register `providers`:
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
ctxmanager.Register(providers []ContextProviders)
```

> **Warning**
> This function in not thread safe. It is prohibited to register and read contexts in the same time.

to register single `provider`:
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
ctxmanager.RegisterSingle(provider ContextProvider)
```

to get data from incoming request and store it to `context.Context`:
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
ctx := ctxmanager.InitContext(context.Context, map[string]interface{})
```

to set `context object` in `context.Context` by contextName if `provider` registered :
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
ctx, err := ctxmanager.SetContextObject(ctx context.Context, contextName string, contextObject interface{})
```

to get `provider` by contextName :
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
contextProvider := ctxmanager.GetProvider(contextName string)
```

to get context data from `context object` which implement interface [SerializableContext](./ctxmanager/context_manager.go#L11):
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
var contextData map[string]string
contextData = ctxmanager.GetSerializableContextData(ctx context.Context)
```

to get context data from `context object` which implement interface [ResponsePropagatableContext](./ctxmanager/context_manager.go#L17):
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
var contextData map[string]string
contextData = ctxmanager.GetResponsePropagatableContextData(ctx context.Context)
```

to create and activate context snapshot: more information [here](#context-snapshots)

To get header names that will be propagated in a scope of incomming request call `GetSerializableHeaders` method:

```go
import (
"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
var headerNames []string
headerNames = ctxmanager.GetSerializableHeaders(ctx context.Context)
```

# Context helper(ctxhelper)

Context helper is a package which contains helpful functions.
* [AddSerializableContextData](#addserializablecontextdata)
* [AddResponsePropagatableContextData](#addresponsepropagatablecontextdata)

#### AddSerializableContextData
If you have a necessity to send context data with outgoing request, you should use this function. 
Also, these context data must implement `SerializableContext` interface.

Function `AddSerializableContextData(ctx context.Context, f func(string, string))` accepts `context.Context` with context data
and func which used to put context data to outgoing request.

Example of Usage:
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxhelper"
    "net/http"
)
request, err := http.NewRequest("GET", "http://example.com", nil)
err = ctxhelper.AddSerializableContextData(ctx, request.Header.Add)
```
In this example, context data from `ctx` which implements `SerializableContext`  will be added to `request.Header`.

#### AddResponsePropagatableContextData

If you have a necessity to get request context data from response, you should use this function.
Also, these context data must implement `ResponsePropagatableContext` interface.

Function `AddResponsePropagatableContextData(ctx context.Context, f func(string, string))` accepts `context.Context` with contextData
and func which used to put context data to response.

Example of Usage:
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxhelper"
    "net/http"
)
http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    err = ctxhelper.AddResponsePropagatableContextData(ctx, w.Header().Add)
}
```
In this example, context data from `ctx` which implements `ResponsePropagatableContext` will be added to `w.Header()`.

# Base contexts

List of base context providers:

* [Accept-Language](#accept-language);
* [Any custom headers](#allowed-headers);
* [API version](#api-version);
* [X-Request-Id](#x-request-id);
* [X-Version](#x-version);
* [X-Version-Name](#x-version-name);
* [X-Nc-Client-Ip](#x-nc-client-ip);
* [Business-Process-Id](#business-process-id);
* [Originating-Bi-Id](#originating-bi-id);


##### How to use

1) Add the core libs with `context-propagation` to go.mod:

```
require github.com/netcracker/qubership-core-lib-go/v3 vx.x.x
```

2) Register context `providers`
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
ctxmanager.Register(providers []ContextProviders)
```

##### Accept-Language

`Accept-Language` context allows propagating 'Accept-Language' headers from one microservice to another. To get context
value, you should call:

Access:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/acceptlanguage"
)
acceptLanguageContextObject, err := acceptlanguage.Of(ctx)
```

Or:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/acceptlanguage"
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

contextObject, err := ctxmanager.GetContextData(ctx, acceptlanguage.ACCEPT_LANGUAGE_CONTEXT_NAME)
acceptLanguageContextObject := contextObject.(AcceptLanguageContextObject)
```

##### Allowed headers

Allows propagating any specified headers. To set a list of headers you should put either
`HEADERS_ALLOWED` environment or set the `headers.allowed` property.
For getting headers.allowed value in our context we use [configloader](../configloader) so you must be sure that your main function contains `configloader#Init(propertySources []*PropertySource)` function

Access:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/allowedheaders"
)

allowedHeadersContextObject, err := allowedheaders.Of(ctx);
```

Or:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/allowedheaders"
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

contextObject, err := ctxmanager.GetContextData(ctx, allowedheaders.ALLOWED_HEADER_CONTEX_NAME)
allowedHeadersContextObject := contextObject.(AllowedHeaderContextObject)
```

If you use application.yaml then you should specify property in the following format:

```text
headers.allowed=myheader1,myheader2,...
```

Otherwise, you need to take care that this parameter is in system#environment.

##### API version

This context `provider` retrieves API version from an incoming request URL and stores it.

Access:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/apiversion"
)
apiVersionContextObject, err := apiversion.Of(ctx)
```

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/apiversion"
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
contextObject, err := ctxmanager.GetContextData(ctx, apiversion.API_VERSION_CONTEXT_NAME)
apiVersionContextObject := contextObject.(ApiVersionContextObject)
```

If request URL does not contain API version then the context contains default value `v1`.

##### X-Request-Id

Propagates and allows to get `X-Request-Id` value. If an incoming request does not contains the `X-Request-Id`
header then a random value is generated.

Access:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
)
xRequestIdContextObject, err := xrequestid.Of(ctx)
```

Or:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
contextObject, err := ctxmanager.GetContextData(ctx, xrequestid.X_REQUEST_ID_COTEXT_NAME)
xRequestIdContextObject := contextObject.(XRequestIdContextObject)
```

##### X-Version

Propagates and allows to get `X-Version` header.

Access:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xversion"
)
xVersionContextObject, err := xversion.Of(ctx)
```

Or:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xversion"
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
contextObject, err := ctxmanager.GetContextData(ctx, xversion.X_REQUEST_ID_COTEXT_NAME)
xVersionContextObject := contextObject.(XVersionContextObject)
```

##### X-Version-Name

Propagates and allows to get `X-Version-Name` header.

Access:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xversionname"
)
xVersionNameContextObject, err := xversionname.Get(ctx)
```

Or:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xversionname"
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)
contextObject, err := ctxmanager.GetContextData(ctx, xversionname.X_VERSION_NAME_CONTEXT_NAME)
xVersionNameContextObject := contextObject.(XVersionNameContextObject)
```


##### Business-Process-Id

Propagates and allows to get and set`Business-Process-Id` header.
Value of header shouldn't be empty. If header is empty and value not set, propagation won't work.

Access (set and get business process id):

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/businessprocess"
)
businesProcessContextObject, err := businessprocess.Of(ctx)
id := businesProcessContextObject.GetBusinessProcessId() // get business process id
businesProcessContextObject.SetBusinessProcessId(id)     // set business process id
```

##### originating-bi-id

Propagates and allows to get and set`originating-bi-id` header.
If header is not set, propagation won't work.
Access (set and get originating bi id):

```go
import (
"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/originatingbiid"
)
OriginatingBiIdContextObject, err := originatingbiid.Of(ctx)
// get originating bi id
id := OriginatingBiIdContextObject.GetOriginatingBiId()

// set originating bi id
ctx, _ = ctxmanager.SetContextObject(ctx, ORIGINATING_BI_ID_CONTEXT_NAME, NewOriginatingBiIdContextObject("some-value"))
outgoingData, err = ctxmanager.GetSerializableContextData(ctx)
```

#### X-Nc-Client-Ip

Propagates and allows to get and set `X-Nc-Client-Ip` header.
The initial value will be the first IP from `X-Forwarded-For` header. If `X-Forwarded-For` header is not set, then `X-Nc-Client-Ip` header value will be used.
If none of these headers are set, propagation won't work.
Access (set and get client ip):

```go
import (
"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/clientip"
)
clientIpContextObject, err := clientip.Of(ctx)
// get client ip
id := clientIpContextObject.GetClientIp()

// set client ip
ctx, _ = ctxmanager.SetContextObject(ctx, X_NC_CLIENT_IP_CONTEXT_NAME, NewClientIpContextObject("some-value"))
outgoingData, err = ctxmanager.GetSerializableContextData(ctx)
```

# How to write own context

The steps below describe how to create your own context `provider`.
You can find some realization [here](baseproviders/xversion)

**The first is** create `context-object`. `Context-object` is a place where you can store data from incoming request

**Note**! Implement `SerializableContext` if you want to propagate data from your context in outgoing request.
The purpose of `Serialize()` method is provide data which should be inserted to outgoing request

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

const ContextObjectName :="Context-object" 
type ContextObject struct {
    value string
}

func NewContextObject(string contextValue) ContextObject{
	return ContextObject{contextValue}
}

func (contextObject ContextObject) Serialize() map[string]string{
    return map[string][]string{ContextObjectName: {contextObject.value}}
}

func Of(ctx context.Context) (*ContextObject, error){
    if ctx.Value(ContextObjectName) == nil{
        return nil, errors.New("context doesn't contain " + ContextObjectName)
    }
    contextProvider, err := ctxmanager.GetProvider(ContextObjectName)
    if err != nil {
        return nil, err
    }
    abstractContextObject := contextProvider.Get(ctx)
    if abstractContextObject == nil {
        return nil, errors.New("acceptLanguage context object is null")
    }
    contextObject := abstractContextObject.(ContextObject)
    return &contextObject, nil
}
```

**Secondly,**  `Provider` - provides information about context to `ctxmanager`. You can use default `provider` or create
your own.

To create your own `provider` you should implement `ContextProvider`

Also, you have to override several functions:

```go
type ContextProvider struct {
}

var logger logging.Logger

func init() {
    logger = logging.GetLogger("context-provider")
}

func (contextProvider ContextProvider) InitLevel() int{
    return 0
}

func (contextProvider ContextProvider) ContextName() string{
    return ContextObjectName
}

func (contextProvider ContextProvider) Provide(ctx context.Context, incomingData map[string]interface{}) context.Context {
    if incomingData[ContextObjectName] == nil {
        return ctx
    }
    return context.WithValue(ctx, ContextObjectName, NewContextObject(incomingData[ContextObjectName].(string)))
}

func (contextProvider ContextProvider) Set(ctx context.Context, object interface{}) (context.Context, error){
    obj, success := object.(ContextObject)
    if !success {
        return ctx, errors.New("incorrect type to set contextObject")
    }
    return context.WithValue(ctx, ContextObjectName, obj)
}

func (contextProvider ContextProvider) Get(ctx context.Context) interface{}{
    return ctx.Value(ContextObjectName)
}

```

# How to override existed context

You have a possibility to override existing context `provider`.
For that you should create a new context `provider` with the same contextName and register it:

```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

ctxmanager.RegisterSingle(NewContextProvider())
```


# Context snapshots

There is a possibility to create a context snapshot - to remember current contexts' data and after to store it.

To get full ContextSnapshot of `context.Context`  use `ctxmanager.CreateFullContextSnapshot`

Example
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

var contextHeadersMap map[string]interface{}
var ctxSnapshot context.context
contextHeadersMap = ctxmanager.CreateFullContextSnapshot(ctx)
ctxSnapshot = ctxmanager.ActivateContextSnapshot(contextHeadersMap)
```

You can also specify names to create context Snapshot 

Example at ctxSnapshot will be only `AcceptLanguage`
```go
import (
    "github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

var contextHeadersMap map[string]interface{}
var ctxSnapshot context.context
contextHeadersMap = ctxmanager.CreateContextSnapshot(ctx, []string{ContextName})
ctxSnapshot = ctxmanager.ActivateContextSnapshot(contextHeadersMap)
```
