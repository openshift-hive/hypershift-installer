package installer

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/yaml"

	operatorv1 "github.com/openshift/api/operator/v1"
	operatorclient "github.com/openshift/client-go/operator/clientset/versioned"
	securityclient "github.com/openshift/client-go/security/clientset/versioned"
	installertypes "github.com/openshift/installer/pkg/types"

	"github.com/openshift-hive/hypershift-installer/pkg/api"
	"github.com/openshift-hive/hypershift-installer/pkg/assets"
	"github.com/openshift-hive/hypershift-installer/pkg/ignition"
	"github.com/openshift-hive/hypershift-installer/pkg/pki"
	"github.com/openshift-hive/hypershift-installer/pkg/render"
)

const (
	externalOauthPort = 8443

	defaultControlPlaneOperatorImage = "registry.svc.ci.openshift.org/hypershift-toolkit/ibm-roks-4.4:control-plane-operator"
	defaultHypershiftOperatorImage   = "quay.io/hypershift/hypershift-operator:latest"

	DefaultAPIServerIPAddress = "172.20.0.1"

	kubeAPIServerServiceName = "kube-apiserver"
	oauthServiceName         = "oauth-openshift"
	vpnServiceName           = "openvpn-server"
	ingressOperatorNamespace = "openshift-ingress-operator"
	hypershiftRouteLabel     = "hypershift.openshift.io/cluster"
	vpnServiceAccountName    = "vpn"
)

var (
	excludeManifests = []string{
		"openshift-apiserver-service.yaml",
		"v4-0-config-system-branding.yaml",
		"oauth-server-service.yaml",
		"kube-apiserver-service.yaml",
	}
	coreScheme = runtime.NewScheme()
	coreCodecs = serializer.NewCodecFactory(coreScheme)

	ignitionDeploymentBytes = assets.MustAsset("ignition-deployment.yaml")
	ignitionServiceBytes    = assets.MustAsset("ignition-service.yaml")
	ignitionRouteBytes      = assets.MustAsset("ignition-route.yaml")
)

func init() {
	if err := corev1.AddToScheme(coreScheme); err != nil {
		panic(err)
	}
}

type CreateClusterOpts struct {
	Directory    string
	ReleaseImage string
	Wait         bool
	DryRun       bool
}

func (o *CreateClusterOpts) Run() error {

	config := &installertypes.InstallConfig{}
	installConfigPath := filepath.Join(o.Directory, installConfigFileName)
	configBytes, err := ioutil.ReadFile(installConfigPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read install-config %s", installConfigPath)
	}
	if err := yaml.Unmarshal(configBytes, config); err != nil {
		return errors.Wrap(err, "failed to parse install-config YAML")
	}
	if o.DryRun && len(o.ReleaseImage) == 0 {
		return errors.New("You must specify a release image when doing a dry run")
	}

	releaseImage := o.ReleaseImage
	name := config.ObjectMeta.Name
	apiAddress := fmt.Sprintf("api.%s", config.BaseDomain)
	oauthAddress := fmt.Sprintf("oauth.%s.%s", name, config.BaseDomain)
	vpnAddress := fmt.Sprintf("vpn.%s.%s", name, config.BaseDomain)
	openshiftClusterIP := "172.30.1.20"

	var dynamicClient dynamic.Interface
	var client kubeclient.Interface
	var cfg *rest.Config

	if !o.DryRun {
		// First, ensure that we can access the host cluster
		var err error
		cfg, err = loadConfig()
		if err != nil {
			return errors.Wrap(err, "cannot access existing cluster; make sure a connection to host cluster is available")
		}

		ctx := context.Background()

		dynamicClient, err = dynamic.NewForConfig(cfg)
		if err != nil {
			return errors.Wrap(err, "cannot obtain dynamic client")
		}
		client, err = kubeclient.NewForConfig(cfg)
		if err != nil {
			return errors.Wrap(err, "failed to obtain a kubernetes client from existing configuration")
		}

		// Start creating resources on management cluster
		_, err = client.CoreV1().Namespaces().Get(ctx, config.ObjectMeta.Name, metav1.GetOptions{})
		if err == nil {
			return fmt.Errorf("target namespace %s already exists on management cluster", name)
		}
		if !apierrors.IsNotFound(err) {
			return errors.Wrap(err, "unexpected error getting namespaces from management cluster")
		}
		log.Infof("Creating namespace %s", name)
		ns := &corev1.Namespace{}
		ns.Name = name
		_, err = client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		if err != nil {
			return errors.Wrapf(err, "failed to create namespace %s", name)
		}

		if releaseImage == "" {
			releaseImage, err = getReleaseImage(dynamicClient)
			if err != nil {
				return errors.Wrap(err, "failed to get release image from parent cluster")
			}
		}

		// Ensure that we can run privileged pods
		securityClient, err := securityclient.NewForConfig(cfg)
		if err != nil {
			return errors.Wrap(err, "failed to create security client")
		}
		if err = ensureVPNSCC(securityClient, name); err != nil {
			return errors.Wrap(err, "failed to ensure privileged SCC for the new namespace")
		}

		// Create pull secret
		log.Infof("Creating pull secret")
		if err := createPullSecret(client, name, config.PullSecret); err != nil {
			return errors.Wrap(err, "failed to create pull secret")
		}

		// Create Kube APIServer service
		log.Infof("Creating Kube API service")
		apiNodePort, err := createKubeAPIServerService(client, name)
		if err != nil {
			return errors.Wrap(err, "failed to create Kube API service")
		}
		log.Infof("Created Kube API service with NodePort %d", apiNodePort)

		log.Infof("Creating VPN service")
		if err := createVPNServerService(client, name); err != nil {
			return errors.Wrap(err, "failed to create vpn server service")
		}
		log.Info("Created VPN service")

		log.Infof("Creating Openshift API service")
		openshiftClusterIP, err = createOpenshiftService(client, name)
		if err != nil {
			return errors.Wrap(err, "failed to create openshift server service")
		}
		log.Infof("Created Openshift API service with cluster IP: %s", openshiftClusterIP)

		log.Info("Creating OAuth service")
		if err := createOauthService(client, name); err != nil {
			return errors.Wrap(err, "error creating service for oauth")
		}

		log.Info("Creating router shard")
		operatorClient, err := operatorclient.NewForConfig(cfg)
		if err := createIngressController(operatorClient, name, config.BaseDomain); err != nil {
			return errors.Wrap(err, "cannot create router shard")
		}

		log.Info("Waiting for API load balancer")
		apiAddress, err = waitForServiceLoadBalancerAddress(client, name, kubeAPIServerServiceName)
		if err != nil {
			return errors.Wrap(err, "failed to get kube API service address")
		}
		log.Debugf("API address from Service Load Balancer: %s", apiAddress)

		log.Info("Waiting for OAuth load balancer")
		oauthAddress, err = waitForServiceLoadBalancerAddress(client, name, oauthServiceName)
		if err != nil {
			return errors.Wrap(err, "failed to get OAuth service address")
		}
		log.Debugf("OAuth address from Service Load Balancer: %s", oauthAddress)

		log.Info("Waiting for VPN load balancer")
		vpnAddress, err = waitForServiceLoadBalancerAddress(client, name, vpnServiceName)
		if err != nil {
			return errors.Wrap(err, "failed to get VPN service address")
		}
		log.Debugf("VPN address from Service Load Balancer: %s", vpnAddress)
	}

	params := api.NewClusterParams()
	params.Namespace = name
	params.ExternalAPIDNSName = apiAddress
	params.ExternalAPIPort = 6443
	params.ExternalAPIAddress = DefaultAPIServerIPAddress
	params.ExternalOpenVPNAddress = vpnAddress
	params.ExternalOpenVPNPort = 1194
	params.ExternalOauthDNSName = oauthAddress
	params.ExternalOauthPort = externalOauthPort
	params.ServiceCIDR = config.Networking.ServiceNetwork[0].String()
	params.PodCIDR = config.Networking.ClusterNetwork[0].CIDR.String()
	params.ReleaseImage = releaseImage
	params.IngressSubdomain = fmt.Sprintf("apps.%s", config.ClusterDomain())
	params.OpenShiftAPIClusterIP = openshiftClusterIP
	params.BaseDomain = config.ClusterDomain()
	params.MachineConfigServerAddress = fmt.Sprintf("ignition-provider-%s.apps.%s", name, config.BaseDomain)
	params.CloudProvider = getProvider(config)
	params.InternalAPIPort = 6443
	params.EtcdClientName = "etcd-client"
	params.NetworkType = "OpenShiftSDN"
	params.ImageRegistryHTTPSecret = generateImageRegistrySecret()
	params.Replicas = "1"
	params.SSHKey = config.SSHKey
	cpOperatorImage := os.Getenv("CONTROL_PLANE_OPERATOR_IMAGE_OVERRIDE")
	if cpOperatorImage == "" {
		params.ControlPlaneOperatorImage = defaultControlPlaneOperatorImage
	} else {
		params.ControlPlaneOperatorImage = cpOperatorImage
	}
	hypershiftOperatorImage := os.Getenv("HYPERSHIFT_OPERATOR_IMAGE_OVERRIDE")
	if hypershiftOperatorImage == "" {
		params.HypershiftOperatorImage = defaultHypershiftOperatorImage
	} else {
		params.HypershiftOperatorImage = hypershiftOperatorImage
	}
	params.HypershiftOperatorControllers = []string{"route-sync", "auto-approver", "kubeadmin-password", "node"}

	workingDir := filepath.Join(o.Directory, "install-files")
	if err = os.Mkdir(workingDir, 0755); err != nil {
		if os.IsExist(err) {
			if err = os.RemoveAll(workingDir); err != nil {
				return err
			}
			if err = os.Mkdir(workingDir, 0755); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	log.Infof("The working directory is %s", workingDir)
	pkiDir := filepath.Join(workingDir, "pki")
	if err = os.MkdirAll(pkiDir, 0755); err != nil {
		return errors.Wrap(err, "cannot create temporary PKI directory")
	}
	log.Info("Generating PKI")
	dhParamsFile := os.Getenv("DH_PARAMS")
	if len(dhParamsFile) > 0 {
		if err = copyFile(dhParamsFile, filepath.Join(pkiDir, "openvpn-dh.pem")); err != nil {
			return errors.Wrapf(err, "cannot copy dh parameters file %s", dhParamsFile)
		}
	}
	if err := pki.GeneratePKI(params, pkiDir); err != nil {
		return fmt.Errorf("failed to generate PKI assets: %v", err)
	}
	manifestsDir := filepath.Join(workingDir, "manifests")
	if err = os.MkdirAll(manifestsDir, 0755); err != nil {
		return fmt.Errorf("cannot create temporary manifests directory: %v", err)
	}
	pullSecretFile := filepath.Join(workingDir, "pull-secret")
	if err = ioutil.WriteFile(pullSecretFile, []byte(config.PullSecret), 0644); err != nil {
		return fmt.Errorf("failed to create temporary pull secret file: %v", err)
	}

	log.Info("Generating ignition for workers")
	if err = ignition.GenerateIgnition(params, []byte(config.SSHKey), pullSecretFile, pkiDir, workingDir); err != nil {
		return fmt.Errorf("cannot generate ignition file for workers: %v", err)
	}

	log.Info("Rendering Manifests")
	render.RenderPKISecrets(pkiDir, manifestsDir, true, true, true)
	caBytes, err := ioutil.ReadFile(filepath.Join(pkiDir, "combined-ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to render PKI secrets: %v", err)
	}
	params.OpenshiftAPIServerCABundle = base64.StdEncoding.EncodeToString(caBytes)

	// Save Params
	clusterYAMLFileName := filepath.Join(workingDir, "cluster.yaml")
	if err != nil {
		return fmt.Errorf("failed to create cluster configuration file: %v", err)
	}
	clusterYAMLBytes, err := yaml.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration into yaml: %v", err)
	}
	if err = ioutil.WriteFile(clusterYAMLFileName, clusterYAMLBytes, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	ibmROKSBinary, err := getROKSBinary()
	if err != nil {
		return fmt.Errorf("Cannot find ibm-roks binary. Either place it in PATH, or set its path in IBM_ROKS: %v", err)
	}
	cmd := exec.Command(ibmROKSBinary, "render",
		"--config", clusterYAMLFileName,
		"--output-dir", manifestsDir,
		"--pull-secret", pullSecretFile,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("Failed to render manifests using IBM ROKS toolkit: %v", err)
	}
	if err = render.RenderClusterManifests(params, pullSecretFile, pkiDir, manifestsDir, true, true, true, true); err != nil {
		return fmt.Errorf("failed to render manifests for cluster: %v", err)
	}
	workerCount := 3
	if len(config.Compute) > 0 && config.Compute[0].Replicas != nil {
		workerCount = int(*config.Compute[0].Replicas)
	}

	if !o.DryRun {
		infraName, _, _, err := getInfrastructureInfo(dynamicClient)
		if err != nil {
			return errors.Wrap(err, "failed to get infrastructure information")
		}
		// Create a machineset for the new cluster's worker nodes
		if err = generateWorkerMachineset(dynamicClient, infraName, name, filepath.Join(manifestsDir, "machineset.json"), workerCount); err != nil {
			return fmt.Errorf("failed to generate worker machineset: %v", err)
		}
	}
	if err = generateUserDataSecret(name, config.BaseDomain, filepath.Join(manifestsDir, "machine-user-data.json")); err != nil {
		return fmt.Errorf("failed to generate user data secret: %v", err)
	}
	kubeadminPassword, err := generateKubeadminPassword()
	if err != nil {
		return fmt.Errorf("failed to generate kubeadmin password: %v", err)
	}
	if err = generateKubeadminPasswordTargetSecret(kubeadminPassword, filepath.Join(manifestsDir, "kubeadmin-secret.json")); err != nil {
		return fmt.Errorf("failed to create kubeadmin secret manifest for target cluster: %v", err)
	}
	if err = generateKubeadminPasswordSecret(kubeadminPassword, filepath.Join(manifestsDir, "kubeadmin-host-secret.json")); err != nil {
		return fmt.Errorf("failed to create kubeadmin secret manifest for management cluster: %v", err)
	}
	if err = generateKubeconfigSecret(filepath.Join(pkiDir, "admin.kubeconfig"), filepath.Join(manifestsDir, "kubeconfig-secret.json")); err != nil {
		return fmt.Errorf("failed to create kubeconfig secret manifest for management cluster: %v", err)
	}
	if err = generateTargetPullSecret([]byte(config.PullSecret), filepath.Join(manifestsDir, "user-pull-secret.json")); err != nil {
		return fmt.Errorf("failed to create pull secret manifest for target cluster: %v", err)
	}

	if !o.DryRun {
		// Create the system branding manifest (cannot be applied because it's too large)
		if err = createBrandingSecret(client, name, filepath.Join(manifestsDir, "v4-0-config-system-branding.yaml")); err != nil {
			return fmt.Errorf("failed to create oauth branding secret: %v", err)
		}
		excludedDir := filepath.Join(workingDir, "excluded")
		err = os.MkdirAll(excludedDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create a temporary directory for excluded manifests")
		}
		log.Infof("Excluded manifests directory: %s", excludedDir)
		if err = applyManifests(cfg, name, manifestsDir, excludeManifests, excludedDir); err != nil {
			return fmt.Errorf("failed to apply manifests: %v", err)
		}
		log.Infof("Cluster resources applied")
	}

	if o.Wait && !o.DryRun {
		log.Infof("Waiting up to 10 minutes for API endpoint to be available.")
		if err = waitForAPIEndpoint(pkiDir, apiAddress); err != nil {
			return fmt.Errorf("failed to access API endpoint: %v", err)
		}
		log.Infof("API is available at %s", fmt.Sprintf("https://%s:6443", apiAddress))

		log.Infof("Waiting up to 5 minutes for bootstrap pod to complete.")
		if err = waitForBootstrapPod(client, name); err != nil {
			return fmt.Errorf("failed to wait for bootstrap pod to complete: %v", err)
		}
		log.Infof("Bootstrap pod has completed.")

		targetClusterCfg, err := getTargetClusterConfig(pkiDir)
		if err != nil {
			return fmt.Errorf("cannot create target cluster client config: %v", err)
		}
		targetClient, err := kubeclient.NewForConfig(targetClusterCfg)
		if err != nil {
			return fmt.Errorf("cannot create target cluster client: %v", err)
		}

		if workerCount == 0 {
			log.Info("No workers have been provisioned for this cluster yet.")
		} else {
			log.Infof("Waiting up to 10 minutes for nodes to be ready.")
			if err = waitForNodesReady(targetClient, workerCount); err != nil {
				return fmt.Errorf("failed to wait for nodes ready: %v", err)
			}
			log.Infof("Nodes (%d) are ready", workerCount)

			log.Infof("Waiting up to 15 minutes for cluster operators to be ready.")
			if err = waitForClusterOperators(targetClusterCfg); err != nil {
				return fmt.Errorf("failed to wait for cluster operators: %v", err)
			}
		}
	}

	log.Infof("Cluster API URL: %s", fmt.Sprintf("https://%s:6443", apiAddress))
	log.Infof("Kubeconfig is available in secret %q in the %s namespace", "admin-kubeconfig", name)
	log.Infof("Console URL:  %s", fmt.Sprintf("https://console-openshift-console.%s", params.IngressSubdomain))
	log.Infof("kubeadmin password is available in secret %q in the %s namespace", "kubeadmin-password", name)
	return nil
}

// generateIgnitionServices will create a Deployment/Service/Route to serve up the ignition config
func generateIgnitionServices(manifestsDir string, ignitionFile string) error {

	if err := ioutil.WriteFile(filepath.Join(manifestsDir, "ignition-deployment.yaml"), ignitionDeploymentBytes, 0644); err != nil {
		log.WithError(err).Error("failed to write out ignition deployment")
		return err
	}

	configMap := &corev1.ConfigMap{}
	configMap.APIVersion = "v1"
	configMap.Name = "ignition-config"

	ignitionFileBytes, err := ioutil.ReadFile(ignitionFile)
	if err != nil {
		log.WithError(err).Error("failed to read in ignition file contents")
		return err
	}
	configMap.Data = map[string]string{
		"worker.ign": string(ignitionFileBytes),
	}
	configMapBytes, err := runtime.Encode(coreCodecs.LegacyCodec(corev1.SchemeGroupVersion), configMap)
	if err != nil {
		log.WithError(err).Error("failed to convert configmap to bytes")
	}
	if err := ioutil.WriteFile(filepath.Join(manifestsDir, "ignition-config.json"), configMapBytes, 0644); err != nil {
		log.WithError(err).Error("failed to write out ignition configmap")
		return err
	}

	if err := ioutil.WriteFile(filepath.Join(manifestsDir, "ignition-service.yaml"), ignitionServiceBytes, 0644); err != nil {
		log.WithError(err).Error("failed to write out ignition service")
		return err
	}

	if err := ioutil.WriteFile(filepath.Join(manifestsDir, "ignition-route.yaml"), ignitionRouteBytes, 0644); err != nil {
		log.WithError(err).Error("failed to write out route")
		return err
	}

	return nil
}

func applyManifests(cfg *rest.Config, namespace, directory string, exclude []string, excludedDir string) error {
	for _, f := range exclude {
		name := filepath.Join(directory, f)
		targetName := filepath.Join(excludedDir, f)
		if err := os.Rename(name, targetName); err != nil {
			return fmt.Errorf("cannot move %s: %v", name, err)
		}
	}
	backoff := wait.Backoff{
		Steps:    3,
		Duration: 10 * time.Second,
		Factor:   1.0,
		Jitter:   0.1,
	}
	attempt := 0
	err := retry.OnError(backoff, func(err error) bool { return true }, func() error {
		attempt++
		log.Infof("Applying Manifests. Attempt %d/3", attempt)
		applier := NewApplier(cfg, namespace)
		return applier.ApplyFile(directory)
	})
	if err != nil {
		return fmt.Errorf("Failed to apply manifests: %v", err)
	}
	return nil
}

func createBrandingSecret(client kubeclient.Interface, namespace, fileName string) error {
	objBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}
	requiredObj, err := runtime.Decode(coreCodecs.UniversalDecoder(corev1.SchemeGroupVersion), objBytes)
	if err != nil {
		return err
	}
	secret, ok := requiredObj.(*corev1.Secret)
	if !ok {
		return fmt.Errorf("object in %s is not a secret", fileName)
	}
	_, err = client.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	return err
}

func createKubeAPIServerService(client kubeclient.Interface, namespace string) (int, error) {
	svc := &corev1.Service{}
	svc.Name = kubeAPIServerServiceName
	svc.Spec.Selector = map[string]string{"app": "kube-apiserver"}
	svc.Spec.Type = corev1.ServiceTypeLoadBalancer
	svc.Spec.Ports = []corev1.ServicePort{
		{
			Port:       6443,
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(6443),
		},
	}
	svc, err := client.CoreV1().Services(namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
	if err != nil {
		return 0, err
	}
	return int(svc.Spec.Ports[0].NodePort), nil
}

func createVPNServerService(client kubeclient.Interface, namespace string) error {
	svc := &corev1.Service{}
	svc.Name = vpnServiceName
	svc.Spec.Selector = map[string]string{"app": "openvpn-server"}
	svc.Spec.Type = corev1.ServiceTypeLoadBalancer
	svc.Spec.Ports = []corev1.ServicePort{
		{
			Port:       1194,
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(1194),
		},
	}
	_, err := client.CoreV1().Services(namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
	return err
}

func createOpenshiftService(client kubeclient.Interface, namespace string) (string, error) {
	svc := &corev1.Service{}
	svc.Name = "openshift-apiserver"
	svc.Spec.Selector = map[string]string{"app": "openshift-apiserver"}
	svc.Spec.Type = corev1.ServiceTypeClusterIP
	svc.Spec.Ports = []corev1.ServicePort{
		{
			Name:       "https",
			Port:       443,
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(8443),
		},
	}
	svc, err := client.CoreV1().Services(namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return svc.Spec.ClusterIP, nil
}

func createOauthService(client kubeclient.Interface, namespace string) error {
	svc := &corev1.Service{}
	svc.Name = oauthServiceName
	svc.Spec.Selector = map[string]string{"app": "oauth-openshift"}
	svc.Spec.Type = corev1.ServiceTypeLoadBalancer
	svc.Spec.Ports = []corev1.ServicePort{
		{
			Name:       "https",
			Port:       8443,
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(6443),
		},
	}
	svc, err := client.CoreV1().Services(namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func createPullSecret(client kubeclient.Interface, namespace, data string) error {
	secret := &corev1.Secret{}
	secret.Name = "pull-secret"
	secret.Data = map[string][]byte{".dockerconfigjson": []byte(data)}
	secret.Type = corev1.SecretTypeDockerConfigJson
	_, err := client.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	retry.RetryOnConflict(retry.DefaultRetry, func() error {
		sa, err := client.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), "default", metav1.GetOptions{})
		if err != nil {
			return err
		}
		sa.ImagePullSecrets = append(sa.ImagePullSecrets, corev1.LocalObjectReference{Name: "pull-secret"})
		_, err = client.CoreV1().ServiceAccounts(namespace).Update(context.TODO(), sa, metav1.UpdateOptions{})
		return err
	})
	return nil
}

func generateTargetPullSecret(data []byte, fileName string) error {
	secret := &corev1.Secret{}
	secret.Name = "pull-secret"
	secret.Namespace = "openshift-config"
	secret.Data = map[string][]byte{".dockerconfigjson": data}
	secret.Type = corev1.SecretTypeDockerConfigJson
	secretBytes, err := runtime.Encode(coreCodecs.LegacyCodec(corev1.SchemeGroupVersion), secret)
	if err != nil {
		return err
	}
	configMap := &corev1.ConfigMap{}
	configMap.APIVersion = "v1"
	configMap.Kind = "ConfigMap"
	configMap.Name = "user-manifest-pullsecret"
	configMap.Data = map[string]string{"data": string(secretBytes)}
	configMapBytes, err := runtime.Encode(coreCodecs.LegacyCodec(corev1.SchemeGroupVersion), configMap)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, configMapBytes, 0644)
}

func getInfrastructureInfo(client dynamic.Interface) (string, string, string, error) {
	infraGroupVersion, err := schema.ParseGroupVersion("config.openshift.io/v1")
	if err != nil {
		return "", "", "", err
	}
	infraGroupVersionResource := infraGroupVersion.WithResource("infrastructures")
	obj, err := client.Resource(infraGroupVersionResource).Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return "", "", "", err
	}
	infraName, exists, err := unstructured.NestedString(obj.Object, "status", "infrastructureName")
	if !exists || err != nil {
		return "", "", "", fmt.Errorf("could not find the infrastructure name in the infrastructure resource: %v", err)
	}
	platformType, _, err := unstructured.NestedString(obj.Object, "status", "platform")
	if err != nil {
		return "", "", "", fmt.Errorf("could not obtain the platform type from the infrastructure resource: %v", err)
	}
	region := ""
	switch platformType {
	case "AWS":
		region, _, _ = unstructured.NestedString(obj.Object, "status", "platformStatus", "aws", "region")
	case "GCP":
		region, _, _ = unstructured.NestedString(obj.Object, "status", "platformStatus", "gcp", "region")
	case "Azure":
		region, _, _ = unstructured.NestedString(obj.Object, "status", "platformStatus", "azure", "resourceGroupName")
	}
	return infraName, platformType, region, nil
}

func getDNSZoneInfo(client dynamic.Interface) (string, string, string, error) {
	configGroupVersion, err := schema.ParseGroupVersion("config.openshift.io/v1")
	if err != nil {
		return "", "", "", err
	}
	dnsGroupVersionResource := configGroupVersion.WithResource("dnses")
	obj, err := client.Resource(dnsGroupVersionResource).Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return "", "", "", err
	}
	publicZoneID, exists, err := unstructured.NestedString(obj.Object, "spec", "publicZone", "id")
	if !exists || err != nil {
		return "", "", "", fmt.Errorf("could not find the dns public zone id in the dns resource: %v", err)
	}
	domain, exists, err := unstructured.NestedString(obj.Object, "spec", "baseDomain")
	if !exists || err != nil {
		return "", "", "", fmt.Errorf("could not find the dns base domain in the dns resource: %v", err)
	}
	parts := strings.Split(domain, ".")
	baseDomain := strings.Join(parts[1:], ".")

	return publicZoneID, baseDomain, domain, nil
}

// loadConfig loads a REST Config as per the rules specified in GetConfig
func loadConfig() (*rest.Config, error) {
	if len(os.Getenv("KUBECONFIG")) > 0 {
		return clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	}
	if c, err := rest.InClusterConfig(); err == nil {
		return c, nil
	}
	if usr, err := user.Current(); err == nil {
		if c, err := clientcmd.BuildConfigFromFlags(
			"", filepath.Join(usr.HomeDir, ".kube", "config")); err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("could not locate a kubeconfig")
}

func getReleaseImage(client dynamic.Interface) (string, error) {
	configGroupVersion, err := schema.ParseGroupVersion("config.openshift.io/v1")
	if err != nil {
		return "", err
	}
	clusterVersionGVR := configGroupVersion.WithResource("clusterversions")
	obj, err := client.Resource(clusterVersionGVR).Get(context.TODO(), "version", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	releaseImage, exists, err := unstructured.NestedString(obj.Object, "status", "desired", "image")
	if !exists || err != nil {
		return "", fmt.Errorf("cannot find release image in cluster version resource")
	}
	return releaseImage, nil
}

func generateWorkerMachineset(client dynamic.Interface, infraName, namespace, fileName string, workerCount int) error {
	machineGV, err := schema.ParseGroupVersion("machine.openshift.io/v1beta1")
	if err != nil {
		return err
	}
	machineSetGVR := machineGV.WithResource("machinesets")
	machineSets, err := client.Resource(machineSetGVR).Namespace("openshift-machine-api").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	if len(machineSets.Items) == 0 {
		return fmt.Errorf("no machinesets found")
	}
	obj := machineSets.Items[0]

	workerName := generateMachineSetName(infraName, namespace, "worker")
	object := obj.Object

	unstructured.RemoveNestedField(object, "status")
	unstructured.RemoveNestedField(object, "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(object, "metadata", "generation")
	unstructured.RemoveNestedField(object, "metadata", "resourceVersion")
	unstructured.RemoveNestedField(object, "metadata", "selfLink")
	unstructured.RemoveNestedField(object, "metadata", "uid")
	unstructured.RemoveNestedField(object, "spec", "template", "spec", "metadata")
	unstructured.RemoveNestedField(object, "spec", "template", "spec", "providerSpec", "value", "publicIp")
	unstructured.SetNestedField(object, int64(workerCount), "spec", "replicas")
	unstructured.SetNestedField(object, workerName, "metadata", "name")
	unstructured.SetNestedField(object, workerName, "spec", "selector", "matchLabels", "machine.openshift.io/cluster-api-machineset")
	unstructured.SetNestedField(object, workerName, "spec", "template", "metadata", "labels", "machine.openshift.io/cluster-api-machineset")
	unstructured.SetNestedField(object, fmt.Sprintf("%s-user-data", namespace), "spec", "template", "spec", "providerSpec", "value", "userDataSecret", "name")
	machineSetBytes, err := json.Marshal(object)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, machineSetBytes, 0644)
}

func generateUserDataSecret(namespace, hyperHostDomain, fileName string) error {
	secret := &corev1.Secret{}
	secret.Kind = "Secret"
	secret.APIVersion = "v1"
	secret.Name = fmt.Sprintf("%s-user-data", namespace)
	secret.Namespace = "openshift-machine-api"

	disableTemplatingValue := []byte(base64.StdEncoding.EncodeToString([]byte("true")))
	userDataValue := []byte(fmt.Sprintf(`{"ignition":{"config":{"append":[{"source":"http://ignition-provider-%s.apps.%s/config/master","verification":{}}]},"security":{},"timeouts":{},"version":"2.2.0"},"networkd":{},"passwd":{},"storage":{},"systemd":{}}`, namespace, hyperHostDomain))

	secret.Data = map[string][]byte{
		"disableTemplating": disableTemplatingValue,
		"userData":          userDataValue,
	}

	secretBytes, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, secretBytes, 0644)
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func ensureVPNSCC(securityClient securityclient.Interface, namespace string) error {
	scc, err := securityClient.SecurityV1().SecurityContextConstraints().Get(context.TODO(), "privileged", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error fetching privileged scc: %v", err)
	}
	userSet := sets.NewString(scc.Users...)
	svcAccount := fmt.Sprintf("system:serviceaccount:%s:%s", namespace, vpnServiceAccountName)
	if userSet.Has(svcAccount) {
		return nil
	}
	userSet.Insert(svcAccount)
	scc.Users = userSet.List()
	_, err = securityClient.SecurityV1().SecurityContextConstraints().Update(context.TODO(), scc, metav1.UpdateOptions{})
	return err
}

func generateKubeadminPasswordTargetSecret(password string, fileName string) error {
	secret := &corev1.Secret{}
	secret.APIVersion = "v1"
	secret.Kind = "Secret"
	secret.Name = "kubeadmin"
	secret.Namespace = "kube-system"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	secret.Data = map[string][]byte{"kubeadmin": passwordHash}

	secretBytes, err := runtime.Encode(coreCodecs.LegacyCodec(corev1.SchemeGroupVersion), secret)
	if err != nil {
		return err
	}
	configMap := &corev1.ConfigMap{}
	configMap.APIVersion = "v1"
	configMap.Kind = "ConfigMap"
	configMap.Name = "user-manifest-kubeadmin-password"
	configMap.Data = map[string]string{"data": string(secretBytes)}
	configMapBytes, err := runtime.Encode(coreCodecs.LegacyCodec(corev1.SchemeGroupVersion), configMap)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, configMapBytes, 0644)
}

func generateKubeadminPasswordSecret(password string, fileName string) error {
	secret := &corev1.Secret{}
	secret.APIVersion = "v1"
	secret.Kind = "Secret"
	secret.Name = "kubeadmin-password"
	secret.Data = map[string][]byte{"password": []byte(password)}
	secretBytes, err := runtime.Encode(coreCodecs.LegacyCodec(corev1.SchemeGroupVersion), secret)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, secretBytes, 0644)
}

func generateKubeconfigSecret(kubeconfigFile, manifestFilename string) error {
	secret := &corev1.Secret{}
	secret.APIVersion = "v1"
	secret.Kind = "Secret"
	secret.Name = "admin-kubeconfig"
	kubeconfigBytes, err := ioutil.ReadFile(kubeconfigFile)
	if err != nil {
		return err
	}
	secret.Data = map[string][]byte{"kubeconfig": kubeconfigBytes}
	secretBytes, err := runtime.Encode(coreCodecs.LegacyCodec(corev1.SchemeGroupVersion), secret)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(manifestFilename, secretBytes, 0644)
}

func updateOAuthDeployment(client kubeclient.Interface, namespace string) error {
	d, err := client.AppsV1().Deployments(namespace).Get(context.TODO(), "oauth-openshift", metav1.GetOptions{})
	if err != nil {
		return err
	}
	annotations := d.Spec.Template.ObjectMeta.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["deployment-refresh"] = fmt.Sprintf("%v", time.Now())
	d.Spec.Template.ObjectMeta.Annotations = annotations
	_, err = client.AppsV1().Deployments(namespace).Update(context.TODO(), d, metav1.UpdateOptions{})
	return err
}

func createIngressController(client operatorclient.Interface, name string, parentDomain string) error {
	// First ensure that the default ingress controller doesn't use routes generated for hypershift clusters
	err := ensureDefaultIngressControllerSelector(client)
	if err != nil {
		return err
	}
	_, err = client.OperatorV1().IngressControllers(ingressOperatorNamespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err == nil {
		client.OperatorV1().IngressControllers(ingressOperatorNamespace).Delete(context.TODO(), name, metav1.DeleteOptions{})

	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("unexpected error fetching existing ingress controller: %v", err)
	}
	ic := &operatorv1.IngressController{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ingressOperatorNamespace,
		},
		Spec: operatorv1.IngressControllerSpec{
			Domain: fmt.Sprintf("apps.%s.%s", name, parentDomain),
			RouteSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					hypershiftRouteLabel: name,
				},
			},
		},
	}
	_, err = client.OperatorV1().IngressControllers(ingressOperatorNamespace).Create(context.TODO(), ic, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ingress controller for %s: %v", name, err)
	}
	return nil
}

func ensureDefaultIngressControllerSelector(client operatorclient.Interface) error {
	defaultIC, err := client.OperatorV1().IngressControllers(ingressOperatorNamespace).Get(context.TODO(), "default", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("cannot fetch default ingress controller: %v", err)
	}
	routeSelector := defaultIC.Spec.RouteSelector
	if routeSelector == nil {
		routeSelector = &metav1.LabelSelector{}
	}
	found := false
	for _, exp := range routeSelector.MatchExpressions {
		if exp.Key == hypershiftRouteLabel && exp.Operator == metav1.LabelSelectorOpDoesNotExist {
			found = true
			break
		}
	}
	if !found {
		routeSelector.MatchExpressions = append(routeSelector.MatchExpressions, metav1.LabelSelectorRequirement{
			Key:      hypershiftRouteLabel,
			Operator: metav1.LabelSelectorOpDoesNotExist,
		})
		defaultIC.Spec.RouteSelector = routeSelector
		_, err = client.OperatorV1().IngressControllers(ingressOperatorNamespace).Update(context.TODO(), defaultIC, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("cannot update default ingress controller: %v", err)
		}
	}
	return nil
}

func generateImageRegistrySecret() string {
	num := make([]byte, 64)
	rand.Read(num)
	return hex.EncodeToString(num)
}

func generateKubeadminPassword() (string, error) {
	const (
		lowerLetters = "abcdefghijkmnopqrstuvwxyz"
		upperLetters = "ABCDEFGHIJKLMNPQRSTUVWXYZ"
		digits       = "23456789"
		all          = lowerLetters + upperLetters + digits
		length       = 23
	)
	var password string
	for i := 0; i < length; i++ {
		n, err := crand.Int(crand.Reader, big.NewInt(int64(len(all))))
		if err != nil {
			return "", err
		}
		newchar := string(all[n.Int64()])
		if password == "" {
			password = newchar
		}
		if i < length-1 {
			n, err = crand.Int(crand.Reader, big.NewInt(int64(len(password)+1)))
			if err != nil {
				return "", err
			}
			j := n.Int64()
			password = password[0:j] + newchar + password[j:]
		}
	}
	pw := []rune(password)
	for _, replace := range []int{5, 11, 17} {
		pw[replace] = '-'
	}
	return string(pw), nil
}

func getTargetClusterConfig(pkiDir string) (*rest.Config, error) {
	return clientcmd.BuildConfigFromFlags("", filepath.Join(pkiDir, "admin.kubeconfig"))
}

func generateLBResourceName(infraName, clusterName, suffix string) string {
	return getName(fmt.Sprintf("%s-%s", infraName, clusterName), suffix, 32)
}

func generateBucketName(infraName, clusterName, suffix string) string {
	return getName(fmt.Sprintf("%s-%s", infraName, clusterName), suffix, 63)
}

func generateMachineSetName(infraName, clusterName, suffix string) string {
	return getName(fmt.Sprintf("%s-%s", infraName, clusterName), suffix, 43)
}

// getName returns a name given a base ("deployment-5") and a suffix ("deploy")
// It will first attempt to join them with a dash. If the resulting name is longer
// than maxLength: if the suffix is too long, it will truncate the base name and add
// an 8-character hash of the [base]-[suffix] string.  If the suffix is not too long,
// it will truncate the base, add the hash of the base and return [base]-[hash]-[suffix]
func getName(base, suffix string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}
	name := fmt.Sprintf("%s-%s", base, suffix)
	if len(name) <= maxLength {
		return name
	}

	baseLength := maxLength - 10 /*length of -hash-*/ - len(suffix)

	// if the suffix is too long, ignore it
	if baseLength < 0 {
		prefix := base[0:min(len(base), max(0, maxLength-9))]
		// Calculate hash on initial base-suffix string
		shortName := fmt.Sprintf("%s-%s", prefix, hash(name))
		return shortName[:min(maxLength, len(shortName))]
	}

	prefix := base[0:baseLength]
	// Calculate hash on initial base-suffix string
	return fmt.Sprintf("%s-%s-%s", prefix, hash(base), suffix)
}

// max returns the greater of its 2 inputs
func max(a, b int) int {
	if b > a {
		return b
	}
	return a
}

// min returns the lesser of its 2 inputs
func min(a, b int) int {
	if b < a {
		return b
	}
	return a
}

// hash calculates the hexadecimal representation (8-chars)
// of the hash of the passed in string using the FNV-a algorithm
func hash(s string) string {
	hash := fnv.New32a()
	hash.Write([]byte(s))
	intHash := hash.Sum32()
	result := fmt.Sprintf("%08x", intHash)
	return result
}

func getProvider(config *installertypes.InstallConfig) string {
	switch {
	case config.Platform.AWS != nil:
		return "AWS"
	case config.Platform.GCP != nil:
		return "GCP"
	case config.Platform.Azure != nil:
		return "Azure"
	default:
		return "None"
	}
}

func getROKSBinary() (string, error) {
	if os.Getenv("IBM_ROKS") != "" {
		return os.Getenv("IBM_ROKS"), nil
	}
	return exec.LookPath("ibm-roks")
}
