package installer

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
)

func UninstallCluster(name string) error {
	// First, ensure that we can access the host cluster
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("cannot access existing cluster; make sure a connection to host cluster is available: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("cannot obtain dynamic client: %v", err)
	}

	infraName, _, err := getInfrastructureInfo(dynamicClient)
	if err != nil {
		return fmt.Errorf("failed to obtain infrastructure info for cluster: %v", err)
	}
	log.Debugf("The management cluster infra name is: %s", infraName)

	dnsZoneID, parentDomain, _, err := getDNSZoneInfo(dynamicClient)
	if err != nil {
		return fmt.Errorf("failed to obtain public zone information: %v", err)
	}
	log.Debugf("Using public DNS Zone: %s and parent suffix: %s", dnsZoneID, parentDomain)

	client, err := kubeclient.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to obtain a kubernetes client from existing configuration: %v", err)
	}
	log.Infof("Removing worker machineset")
	if err = removeWorkerMachineset(dynamicClient, infraName, name); err != nil {
		return fmt.Errorf("failed to remove worker machineset: %v", err)
	}

	log.Info("Removing cluster namespace")
	if err = client.CoreV1().Namespaces().Delete(name, &metav1.DeleteOptions{}); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete namespace %s: %v", name, err)
		}
	}

	return nil
}

func removeWorkerMachineset(client dynamic.Interface, infraName, namespace string) error {
	name := generateMachineSetName(infraName, namespace, "worker")
	machineGV, err := schema.ParseGroupVersion("machine.openshift.io/v1beta1")
	if err != nil {
		return err
	}
	machineSetGVR := machineGV.WithResource("machinesets")
	err = client.Resource(machineSetGVR).Namespace("openshift-machine-api").Delete(name, &metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}
