package machineset

import (
	"fmt"
	"strings"
)

func TransformLabelsFn(clusterNameTransform, machineSetNameTransform ValueTransformFunc) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		labels, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("expecting map[string]interface{} type, got %T", value)
		}
		dest := map[string]interface{}{}
		var err error
		for key, value := range labels {
			switch key {
			case "machine.openshift.io/cluster-api-cluster":
				dest[key], err = clusterNameTransform(value)
				if err != nil {
					return nil, err
				}
			case "machine.openshift.io/cluster-api-machineset":
				dest[key], err = machineSetNameTransform(value)
				if err != nil {
					return nil, err
				}
			default:
				dest[key] = value
			}
		}
		return dest, nil
	}
}

func TransformClusterNameFn(sourceInfraID, destInfraID string) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		if value != sourceInfraID {
			return "", fmt.Errorf("unexpected cluster name: %s", value)
		}
		return destInfraID, nil
	}
}

func TransformMachineSetNameFn(sourceInfraID, destInfraID, clusterName string) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		stringValue, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("expected value of type string, got %T", value)
		}
		expectedPrefix := fmt.Sprintf("%s-worker-", sourceInfraID)
		if !strings.HasPrefix(stringValue, fmt.Sprintf("%s-worker-", sourceInfraID)) {
			return value, nil
		}
		return fmt.Sprintf("%s-%s-%s", destInfraID, clusterName, stringValue[len(expectedPrefix):]), nil
	}
}

func TransformPrefixFn(sourceInfraID, destInfraID string) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		strValue, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("expected value of type string, got %T", value)
		}
		if !strings.HasPrefix(strValue, fmt.Sprintf("%s-", sourceInfraID)) {
			return value, nil
		}
		return fmt.Sprintf("%s%s", destInfraID, strValue[len(sourceInfraID):]), nil
	}
}

func TransformSecretNameFn(clusterName string) ValueTransformFunc {
	return func(value interface{}) (interface{}, error) {
		return fmt.Sprintf("%s-user-data", clusterName), nil
	}
}
