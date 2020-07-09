package installer

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	gocidr "github.com/apparentlymart/go-cidr/cidr"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"

	"github.com/openshift/installer/pkg/ipnet"
	installertypes "github.com/openshift/installer/pkg/types"
	"github.com/openshift/installer/pkg/types/aws"
	"github.com/openshift/installer/pkg/types/azure"
	"github.com/openshift/installer/pkg/types/gcp"
)

const installConfigFileName = "install-config.yaml"

type CreateInstallConfigOpts struct {
	Name           string
	Directory      string
	PullSecretFile string
	SSHKeyFile     string
	Local          bool
}

func (o *CreateInstallConfigOpts) Run() error {
	// First, ensure that we can access the host cluster
	var sshKey, pullSecret, platformType, region, baseDomain string
	var clusterPodCIDR, clusterServiceCIDR *net.IPNet
	if len(o.SSHKeyFile) > 0 {
		b, err := ioutil.ReadFile(o.SSHKeyFile)
		if err != nil {
			return errors.Wrapf(err, "cannot read SSH key file %s", o.SSHKeyFile)
		}
		sshKey = string(b)
	}
	if len(o.PullSecretFile) > 0 {
		b, err := ioutil.ReadFile(o.PullSecretFile)
		if err != nil {
			return errors.Wrapf(err, "cannot read pull secret file %s", o.PullSecretFile)
		}
		pullSecret = string(b)
	}
	if o.Local {
		platformType = "AWS"
		region = "us-east-1"
		_, clusterPodCIDR, _ = net.ParseCIDR("10.132.0.0/14")
		_, clusterServiceCIDR, _ = net.ParseCIDR("172.31.0.0/16")
		baseDomain = "cluster.openshift.com"
	} else {
		cfg, err := loadConfig()
		if err != nil {
			return fmt.Errorf("cannot access existing cluster; make sure a connection to host cluster is available: %v", err)
		}
		dynamicClient, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("cannot obtain dynamic client: %v", err)
		}
		client, err := kubeclient.NewForConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to obtain a kubernetes client from existing configuration: %v", err)
		}

		// Extract config information from management cluster
		if len(sshKey) == 0 {
			b, err := getSSHPublicKey(dynamicClient)
			if err != nil {
				return fmt.Errorf("failed to fetch an SSH public key from existing cluster: %v", err)
			}
			log.Debugf("The SSH public key is: %s", string(sshKey))
			sshKey = string(b)
		}

		if len(pullSecret) == 0 {
			pullSecret, err = getPullSecret(client)
			if err != nil {
				return fmt.Errorf("failed to obtain a pull secret from cluster: %v", err)
			}
			log.Debugf("The pull secret is: %v", pullSecret)
		}

		_, platformType, region, err = getInfrastructureInfo(dynamicClient)
		if err != nil {
			return fmt.Errorf("failed to obtain infrastructure info for cluster: %v", err)
		}

		serviceCIDR, podCIDR, err := getNetworkInfo(dynamicClient)
		if err != nil {
			return fmt.Errorf("failed to obtain network info for cluster: %v", err)
		}

		dnsZoneID, parentDomain, hyperHostDomain, err := getDNSZoneInfo(dynamicClient)
		if err != nil {
			return fmt.Errorf("failed to obtain public zone information: %v", err)
		}
		log.Debugf("Using public DNS Zone: %s and parent suffix: %s", dnsZoneID, parentDomain)
		baseDomain = hyperHostDomain

		_, serviceCIDRNet, err := net.ParseCIDR(serviceCIDR)
		if err != nil {
			return fmt.Errorf("cannot parse service CIDR %s: %v", serviceCIDR, err)
		}

		_, podCIDRNet, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return fmt.Errorf("cannot parse pod CIDR %s: %v", podCIDR, err)
		}

		serviceCIDRPrefixLen, _ := serviceCIDRNet.Mask.Size()
		var exceedsMax bool
		clusterServiceCIDR, exceedsMax = gocidr.NextSubnet(serviceCIDRNet, serviceCIDRPrefixLen)
		if exceedsMax {
			return fmt.Errorf("cluster service CIDR exceeds max address space")
		}

		podCIDRPrefixLen, _ := podCIDRNet.Mask.Size()
		clusterPodCIDR, exceedsMax = gocidr.NextSubnet(podCIDRNet, podCIDRPrefixLen)
		if exceedsMax {
			return fmt.Errorf("cluster pod CIDR exceeds max address space")
		}
	}

	installConfig := &installertypes.InstallConfig{}
	installConfig.ObjectMeta.Name = o.Name
	installConfig.PullSecret = pullSecret
	installConfig.SSHKey = string(sshKey)
	installConfig.BaseDomain = baseDomain

	networking := &installertypes.Networking{}
	networking.NetworkType = "OpenShiftSDN"
	networking.ClusterNetwork = []installertypes.ClusterNetworkEntry{
		{
			CIDR:       ipnet.IPNet{IPNet: *clusterPodCIDR},
			HostPrefix: 23,
		},
	}
	networking.ServiceNetwork = []ipnet.IPNet{
		{
			IPNet: *clusterServiceCIDR,
		},
	}
	installConfig.Networking = networking
	var replicas int64 = 3
	installConfig.Compute = []installertypes.MachinePool{
		{
			Name:     "worker",
			Replicas: &replicas,
		},
	}
	switch platformType {
	case "AWS":
		installConfig.Platform.AWS = &aws.Platform{Region: region}
	case "GCP":
		installConfig.Platform.GCP = &gcp.Platform{Region: region}
	case "Azure":
		installConfig.Platform.Azure = &azure.Platform{Region: region}
	}
	b, err := yaml.Marshal(installConfig)
	if err != nil {
		return err
	}
	if len(o.Directory) > 0 {
		if err = os.MkdirAll(o.Directory, 0755); err != nil {
			return err
		}
	}
	installConfigFilePath := filepath.Join(o.Directory, installConfigFileName)
	return ioutil.WriteFile(installConfigFilePath, b, 0644)
}

func getSSHPublicKey(client dynamic.Interface) ([]byte, error) {
	machineConfigGroupVersion, err := schema.ParseGroupVersion("machineconfiguration.openshift.io/v1")
	if err != nil {
		return nil, err
	}
	machineConfigGroupVersionResource := machineConfigGroupVersion.WithResource("machineconfigs")
	obj, err := client.Resource(machineConfigGroupVersionResource).Get(context.TODO(), "99-master-ssh", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	obj.GetName()
	users, exists, err := unstructured.NestedSlice(obj.Object, "spec", "config", "passwd", "users")
	if !exists || err != nil {
		return nil, fmt.Errorf("could not find users slice in ssh machine config: %v", err)
	}
	keys, exists, err := unstructured.NestedStringSlice(users[0].(map[string]interface{}), "sshAuthorizedKeys")
	if !exists || err != nil {
		return nil, fmt.Errorf("could not find authorized keys for machine config: %v", err)
	}
	return []byte(keys[0]), nil
}

func getPullSecret(client kubeclient.Interface) (string, error) {
	secret, err := client.CoreV1().Secrets("openshift-config").Get(context.TODO(), "pull-secret", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	pullSecret, ok := secret.Data[".dockerconfigjson"]
	if !ok {
		return "", fmt.Errorf("did not find pull secret data in secret")
	}
	return string(pullSecret), nil
}

func getNetworkInfo(client dynamic.Interface) (string, string, error) {
	configGroupVersion, err := schema.ParseGroupVersion("config.openshift.io/v1")
	if err != nil {
		return "", "", err
	}
	networkGroupVersionResource := configGroupVersion.WithResource("networks")
	obj, err := client.Resource(networkGroupVersionResource).Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	serviceNetworks, exists, err := unstructured.NestedSlice(obj.Object, "status", "serviceNetwork")
	if !exists || err != nil || len(serviceNetworks) == 0 {
		return "", "", fmt.Errorf("could not find service networks in the network status: %v", err)
	}
	serviceCIDR := serviceNetworks[0].(string)

	podNetworks, exists, err := unstructured.NestedSlice(obj.Object, "status", "clusterNetwork")
	if !exists || err != nil || len(podNetworks) == 0 {
		return "", "", fmt.Errorf("could not find cluster networks in the network status: %v", err)
	}
	podCIDR, exists, err := unstructured.NestedString(podNetworks[0].(map[string]interface{}), "cidr")
	if !exists || err != nil {
		return "", "", fmt.Errorf("cannot find cluster network cidr: %v", err)
	}
	return serviceCIDR, podCIDR, nil
}
