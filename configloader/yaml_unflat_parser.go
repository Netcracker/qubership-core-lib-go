package configloader

import (
	"github.com/knadh/koanf/maps"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/v2"
)

type flattenYAMLParser struct{}

func (y flattenYAMLParser) Unmarshal(bytes []byte) (map[string]interface{}, error) {
	yamlParser := &yaml.YAML{}
	unmarshal, err := yamlParser.Unmarshal(bytes)
	if err != nil {
		return nil, err
	}
	// because all nested maps should be map[string]interface{}
	maps.IntfaceKeysToStrings(unmarshal)
	flattenedResult, _ := maps.Flatten(unmarshal, []string{}, ".")
	return flattenedResult, nil
}

func (y flattenYAMLParser) Marshal(m map[string]interface{}) ([]byte, error) {
	yamlParser := &yaml.YAML{}
	return yamlParser.Marshal(m)
}

type flattenEnvProvider struct {
	koanfEnv *env.Env
}

func Provider(prefix, delim string, cb func(s string) string) *flattenEnvProvider {
	return &flattenEnvProvider{koanfEnv: env.Provider(prefix, delim, cb)}
}

// ReadBytes is not supported by the env provider.
func (e flattenEnvProvider) ReadBytes(_ *koanf.Koanf) ([]byte, error) {
	return e.koanfEnv.ReadBytes()
}

// Read reads all available environment variables into a key:value map
// and returns it.
func (e flattenEnvProvider) Read(_ *koanf.Koanf) (map[string]interface{}, error) {
	unflattenMap, err := e.koanfEnv.Read()
	if err != nil {
		return nil, err
	}
	flattenMap, _ := maps.Flatten(unflattenMap, []string{}, ".")
	return flattenMap, nil
}
