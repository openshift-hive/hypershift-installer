package machineset

import (
	"fmt"
	"io/ioutil"
	"reflect"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	yamlserializer "k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"sigs.k8s.io/yaml"
)

func NewJSONPathTransformer(t ...ValueTransformer) JSONPathTransformer {
	return JSONPathTransformer(t)
}

type ValueTransformFunc func(interface{}) (interface{}, error)

type ValueTransformer struct {
	Path      []string
	Transform ValueTransformFunc
}

func NewValueTransformer(f ValueTransformFunc, path ...string) ValueTransformer {
	return ValueTransformer{
		Transform: f,
		Path:      path,
	}
}

type JSONPathTransformer []ValueTransformer

func (t JSONPathTransformer) TransformManifest(sourcePath, destPath string) error {
	objBytes, err := ioutil.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", sourcePath, err)
	}
	codec := yamlserializer.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	u := &unstructured.Unstructured{}
	if _, _, err = codec.Decode(objBytes, nil, u); err != nil {
		return fmt.Errorf("failed to decode %s (%s): %v", sourcePath, string(objBytes), err)
	}

	for _, pt := range t {
		_, err := t.transformValue(u.Object, pt.Path, pt.Transform)
		if err != nil {
			return fmt.Errorf("failed to transform path %v: %v", pt.Path, err)
		}
	}

	jsonData, err := u.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal JSON for unstructured resource %v: %v", u.GetName(), err)
	}
	yamlData, err := yaml.JSONToYAML(jsonData)
	if err != nil {
		return fmt.Errorf("failed to convert JSON data (%s) to YAML: %v", string(jsonData), err)
	}
	return ioutil.WriteFile(destPath, yamlData, 0644)
}

func (t JSONPathTransformer) transformValue(value interface{}, path []string, transformFn ValueTransformFunc) (interface{}, error) {
	if reflect.TypeOf(value).Kind() == reflect.Slice {
		return t.transformSliceValue(value, path, transformFn)
	}
	if len(path) == 0 {
		return transformFn(value)
	}
	mapValue, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T: expected map", value)
	}
	childObj, ok := mapValue[path[0]]
	if !ok {
		return value, nil
	}
	transformed, err := t.transformValue(childObj, path[1:], transformFn)
	if err != nil {
		return nil, fmt.Errorf("failed to transform child at %s: %v", path[0], err)
	}
	mapValue[path[0]] = transformed
	return value, nil
}

func (t JSONPathTransformer) transformSliceValue(slice interface{}, path []string, transformFn func(interface{}) (interface{}, error)) (interface{}, error) {
	value := reflect.ValueOf(slice)
	for i := 0; i < value.Len(); i++ {
		obj := value.Index(i).Interface()
		transformed, err := t.transformValue(obj, path, transformFn)
		if err != nil {
			return nil, fmt.Errorf("error transforming value at %d: %v", i, err)
		}
		value.Index(i).Set(reflect.ValueOf(transformed))
	}
	return value.Interface(), nil
}
