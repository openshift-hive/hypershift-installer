package machineset

import (
	"fmt"
	"strings"
)

type azureProvider struct{}

func init() {
	RegisterProvider(&azureProvider{})
}

func (*azureProvider) CanHandle(platformType string) bool {
	return platformType == "Azure"
}

func (*azureProvider) Transformer(sourceInfraID, destInfraID, clusterName string) ManifestTransformer {
	msNameFn := TransformMachineSetNameFn(sourceInfraID, destInfraID, clusterName)
	clusterNameFn := TransformClusterNameFn(sourceInfraID, destInfraID)
	labelsFn := TransformLabelsFn(clusterNameFn, msNameFn)
	prefixFn := TransformPrefixFn(sourceInfraID, destInfraID)
	secretFn := TransformSecretNameFn(clusterName)
	resIDFn := TransformAzureResourceIDFn(sourceInfraID, destInfraID)
	vt := NewValueTransformer

	return NewJSONPathTransformer(
		vt(msNameFn, "metadata", "name"),
		vt(labelsFn, "metadata", "labels"),
		vt(labelsFn, "spec", "selector", "matchLabels"),
		vt(labelsFn, "spec", "template", "metadata", "labels"),
		vt(resIDFn, "spec", "template", "spec", "providerSpec", "value", "image", "resourceID"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "managedIdentity"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "networkResourceGroup"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "resourceGroup"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "subnet"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "vnet"),
		vt(secretFn, "spec", "template", "spec", "providerSpec", "value", "userDataSecret", "name"),
	)
}

func TransformAzureResourceIDFn(sourceInfraID, destInfraID string) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("expected value of type string, got %T", value)
		}
		result := strings.ReplaceAll(str, sourceInfraID, destInfraID)
		return result, nil
	}
}
