package machineset

import (
	"fmt"
	"strings"
)

type gcpProvider struct{}

func init() {
	RegisterProvider(&gcpProvider{})
}

func (*gcpProvider) CanHandle(platformType string) bool {
	return platformType == "GCP"
}

func (*gcpProvider) Transformer(sourceInfraID, destInfraID, clusterName string) ManifestTransformer {
	msNameFn := TransformGCPMachineSetNameFn(sourceInfraID, destInfraID, clusterName)
	clusterNameFn := TransformClusterNameFn(sourceInfraID, destInfraID)
	labelsFn := TransformLabelsFn(clusterNameFn, msNameFn)
	prefixFn := TransformPrefixFn(sourceInfraID, destInfraID)
	secretFn := TransformSecretNameFn(clusterName)
	vt := NewValueTransformer

	return NewJSONPathTransformer(
		vt(msNameFn, "metadata", "name"),
		vt(labelsFn, "metadata", "labels"),
		vt(labelsFn, "spec", "selector", "matchLabels"),
		vt(labelsFn, "spec", "template", "metadata", "labels"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "disks", "image"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "networkInterfaces", "network"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "networkInterfaces", "subnetwork"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "serviceAccounts", "email"),
		vt(prefixFn, "spec", "template", "spec", "providerSpec", "value", "tags"),
		vt(secretFn, "spec", "template", "spec", "providerSpec", "value", "userDataSecret", "name"),
	)
}

func TransformGCPMachineSetNameFn(sourceInfraID, destInfraID, clusterName string) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("expected value of type string, got %T", value)
		}
		if !strings.HasPrefix(str, sourceInfraID+"-") {
			return value, nil
		}
		remaining := str[len(sourceInfraID)+1:]
		parts := strings.Split(remaining, "-")
		return fmt.Sprintf("%s-%s-%s", destInfraID, clusterName, strings.Join(parts[1:], "-")), nil
	}
}
