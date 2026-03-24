package ctxmanager

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

// Context objects which implement SerializableContext will be used to propagate their value to outgoing requests
type SerializableContext interface {
	// Serialize method is used to get context data which should be injected to an outgoing request
	Serialize() (map[string]string, error)
}

// Context objects which implement ResponsePropagatableContext will be used to propagate their value to incoming response
type ResponsePropagatableContext interface {
	// Propagate method is used to get context data which should be injected to response
	Propagate() (map[string]string, error)
}

// All contexts must implement ContextProvider interface. ContextProvider allow to set, get and create context object.
// Context object is a container for context data.
type ContextProvider interface {
	// Provide create context object and store it in context.Context
	// Provide must use context.WithValue to append context.Context
	Provide(ctx context.Context, incomingData map[string]interface{}) context.Context
	// InitLevel method returns priority of processing context provider
	// If you don't care about priority set InitLevel 0
	InitLevel() int
	// ContextName method returns the name of context
	ContextName() string
	// Set used to set context object to context.Context
	// method takes context object which will replace current context object in context.Context
	// In implementation you should use context.WithValue for producing a new context.Context which contains passed context.Context
	Set(ctx context.Context, contextObject interface{}) (context.Context, error)
	// Get returns context object from context.Context
	// Method must return object, NOT objectPtr
	Get(ctx context.Context) interface{}
}

var logger logging.Logger

func init() {
	logger = logging.GetLogger("context-manager")
}

var contextProviders = map[string]ContextProvider{}
var sortedContextProviders []ContextProvider

// Allows to override existing context provider
// This function in not thread safe. It is prohibited to register and read contexts in the same time.
func Register(providers []ContextProvider) {
	for _, provider := range providers {
		contextName := provider.ContextName()
		if contextProviders[contextName] != nil && contextProviders[contextName].InitLevel() > provider.InitLevel() {
			logger.Debug("context=%s  were skipped with level:%d", provider.ContextName(), provider.InitLevel())
			break
		}
		contextProviders[provider.ContextName()] = provider
		logger.Debug("context=%s registered", provider.ContextName())
	}
	var allProviders []ContextProvider
	for _, provider := range contextProviders {
		allProviders = append(allProviders, provider)
		logger.Debug("context=%s added with init level: %d", provider.ContextName(), provider.InitLevel())
	}
	sortedContextProviders = sortByInitLevel(allProviders)
	logger.Info("contexts successfully registered")
}

func RegisterSingle(provider ContextProvider) {
	contextProviders[provider.ContextName()] = provider
	logger.Debug("context=%s registered", provider.ContextName())
	var allProviders []ContextProvider
	for _, prov := range contextProviders {
		allProviders = append(allProviders, prov)
	}
	sortedContextProviders = sortByInitLevel(allProviders)
	logger.Info("context successfully registered")
}

func InitContext(ctx context.Context, incomingData map[string]interface{}) context.Context {
	//TODO uncomment this before a major release
	//incomingData = dataMapToLowerCase(incomingData)
	for _, contextProvider := range sortedContextProviders {
		ctx = contextProvider.Provide(ctx, incomingData)
	}
	return ctx
}

func dataMapToLowerCase(incomingData map[string]interface{}) map[string]interface{} {
	incomingDataLowerCase := map[string]interface{}{}
	for key, value := range incomingData {
		incomingDataLowerCase[strings.ToLower(key)] = value
	}
	return incomingDataLowerCase
}

func SetContextObject(ctx context.Context, contextName string, contextObject interface{}) (context.Context, error) {
	if contextProviders[contextName] == nil {
		return nil, errors.New("context=" + contextName + " isn't registered")
	}
	return contextProviders[contextName].Set(ctx, contextObject)
}

func GetContextObject(ctx context.Context, contextName string) (interface{}, error) {
	if contextProviders[contextName] == nil {
		return nil, errors.New("context=" + contextName + "isn't registered")
	}
	return contextProviders[contextName].Get(ctx), nil
}

func GetProvider(contextName string) (ContextProvider, error) {
	if contextProviders[contextName] == nil {
		return nil, errors.New("context=" + contextName + " isn't registered")
	}
	return contextProviders[contextName], nil
}

func GetSerializableContextData(ctx context.Context) (map[string]string, error) {
	resultMap := map[string]string{}
	logger.Debug("get serializable contextData")
	for _, provider := range sortedContextProviders {
		if contextObject := provider.Get(ctx); contextObject != nil {
			if serializablePropagator, isSerializable := (contextObject).(SerializableContext); isSerializable {
				serializableData, err := serializablePropagator.Serialize()
				if err != nil {
					return nil, err
				}
				if serializableData != nil {
					for key, value := range serializableData {
						resultMap[key] = value
					}
				}
			}
		}
	}
	logger.Debug("serializable context data=%v was successfully collected", resultMap)
	return resultMap, nil
}

func GetDownstreamHeaders(ctx context.Context) ([]string, error) {
	headersMap, err := GetSerializableContextData(ctx)
	if err != nil {
		return nil, err
	}

	var headers []string
	for header := range headersMap {
		headers = append(headers, header)
	}
	return headers, nil
}
func GetResponsePropagatableContextData(ctx context.Context) (map[string]string, error) {
	resultMap := map[string]string{}
	logger.Debug("get response propagatable contextData")
	for _, provider := range sortedContextProviders {
		if contextObject := provider.Get(ctx); contextObject != nil {
			if responsePropagatable, isPropagatable := (contextObject).(ResponsePropagatableContext); isPropagatable {
				propagatableData, err := responsePropagatable.Propagate()
				if err != nil {
					return nil, err
				}
				if propagatableData != nil {
					for key, value := range propagatableData {
						resultMap[key] = value
					}
				}
			}
		}
	}
	logger.Debug("response propagatable context data=%v was successfully collected", resultMap)
	return resultMap, nil
}

func CreateContextSnapshot(ctx context.Context, contextNames []string) map[string]interface{} {
	logger.Debug("start create context snapshot")
	resultMap := make(map[string]interface{})
	for _, contextName := range contextNames {
		if contextProvider := contextProviders[contextName]; contextProvider != nil {
			contextObject := contextProvider.Get(ctx)
			if contextObject != nil {
				resultMap[contextName] = contextObject
			}
		}
	}
	logger.Debug("success create context snapshot")
	return resultMap
}

func CreateFullContextSnapshot(ctx context.Context) map[string]interface{} {
	logger.Debug("start create full context snapshot")
	resultMap := make(map[string]interface{})
	for _, provider := range sortedContextProviders {
		if provider != nil {
			contextObject := provider.Get(ctx)
			if contextObject == nil {
				logger.Error("context object is null")
			} else {
				resultMap[provider.ContextName()] = contextObject
			}
		}
	}
	logger.Debug("success create full context snapshot")
	return resultMap
}

func ActivateContextSnapshot(contextSnapshot map[string]interface{}) (context.Context, error) {
	logger.Debug("start activate context snapshot")
	ctx := context.Background()
	var err error
	for contextName, contextObject := range contextSnapshot {
		ctx, err = contextProviders[contextName].Set(ctx, contextObject)
		if err != nil {
			return nil, err
		}
	}
	logger.Debug("success activate context snapshot")
	return ctx, nil
}

func sortByInitLevel(providers []ContextProvider) []ContextProvider {
	logger.Debug("sort providers by initLevel")
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].InitLevel() < providers[j].InitLevel()
	})
	return providers
}
