package machineset

import (
	"fmt"
)

type awsProvider struct{}

func init() {
	RegisterProvider(&awsProvider{})
}

func (t *awsProvider) CanHandle(platformType string) bool {
	return platformType == "AWS"
}

func (t *awsProvider) Transformer(sourceInfraID, destInfraID, clusterName string) ManifestTransformer {
	msNameFn := TransformMachineSetNameFn(sourceInfraID, destInfraID, clusterName)
	clusterNameFn := TransformClusterNameFn(sourceInfraID, destInfraID)
	labelsFn := TransformLabelsFn(clusterNameFn, msNameFn)
	prefixFn := TransformPrefixFn(sourceInfraID, destInfraID)
	tagFn := TransformTagFn(sourceInfraID, destInfraID)
	secretFn := TransformSecretNameFn(clusterName)
	vt := NewValueTransformer

	return NewJSONPathTransformer(
		vt(msNameFn, "metadata", "name"),
		vt(labelsFn, "metadata", "labels"),
		vt(labelsFn, "spec", "selector", "matchLabels"),
		vt(labelsFn, "spec", "template", "metadata", "labels"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "iamInstanceProfile", "id"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "securityGroups", "filters", "values"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "subnet", "filters", "values"),
		vt(tagFn, "spec", "template", "spec", "providerSpec", "value", "tags", "name"),
		vt(secretFn, "spec", "template", "spec", "providerSpec", "value", "userDataSecret", "name"),
	)
}

func TransformTagFn(sourceInfraID, destInfraID string) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", value)
		}
		if str != fmt.Sprintf("kubernetes.io/cluster/%s", sourceInfraID) {
			return value, nil
		}
		return fmt.Sprintf("kubernetes.io/cluster/%s", destInfraID), nil
	}
}
