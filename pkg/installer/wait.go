package installer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	clientwatch "k8s.io/client-go/tools/watch"

	configapi "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	"github.com/pkg/errors"
)

const (
	apiEndpointTimeout           = 10 * time.Minute
	nodesReadyTimeout            = 15 * time.Minute
	clusterOperatorsReadyTimeout = 15 * time.Minute
	serviceLoadBalancerTimeout   = 5 * time.Minute
)

func waitForAPIEndpoint(pkiDir, apiAddress string) error {
	caCertBytes, err := ioutil.ReadFile(filepath.Join(pkiDir, "root-ca.crt"))
	if err != nil {
		return fmt.Errorf("cannot read CA file: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertBytes)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
		Timeout: 3 * time.Second,
	}

	url := fmt.Sprintf("https://%s:6443/healthz", apiAddress)

	err = wait.PollImmediate(10*time.Second, apiEndpointTimeout, func() (bool, error) {
		resp, err := client.Get(url)
		if err != nil {
			return false, nil
		}
		return resp.StatusCode == http.StatusOK, nil
	})
	return err
}

func waitForNodesReady(client kubeclient.Interface, expectedCount int) error {
	ctx, cancel := context.WithTimeout(context.Background(), nodesReadyTimeout)
	defer cancel()
	listWatcher := cache.NewListWatchFromClient(client.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	allNodesReady := func(event watch.Event) (bool, error) {
		list, err := listWatcher.List(metav1.ListOptions{})
		if err != nil {
			return false, fmt.Errorf("an error occurred listing nodes: %v", err)
		}
		nodeList, ok := list.(*corev1.NodeList)
		if !ok {
			return false, fmt.Errorf("unexpected object from list function: %t", list)
		}
		if len(nodeList.Items) < expectedCount {
			return false, nil
		}

		for _, node := range nodeList.Items {
			ready := false
			for _, cond := range node.Status.Conditions {
				if cond.Type == corev1.NodeReady {
					if cond.Status == corev1.ConditionTrue {
						ready = true
						break
					} else {
						return false, nil
					}
				}
			}
			if !ready {
				return false, nil
			}
		}
		return true, nil
	}
	_, err := clientwatch.UntilWithSync(ctx, listWatcher, &corev1.Node{}, nil, allNodesReady)
	return err
}

func waitForClusterOperators(cfg *rest.Config) error {
	client, err := configclient.NewForConfig(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), clusterOperatorsReadyTimeout)
	defer cancel()
	listWatcher := cache.NewListWatchFromClient(client.RESTClient(), "clusteroperators", "", fields.Everything())

	clusterOperatorsAreAvailable := func(event watch.Event) (bool, error) {
		list, err := listWatcher.List(metav1.ListOptions{})
		if err != nil {
			return false, fmt.Errorf("an error occurred listing cluster operators: %v", err)
		}
		operatorList, ok := list.(*configapi.ClusterOperatorList)
		if !ok {
			return false, fmt.Errorf("unexpected object from list function: %t", list)
		}

		for _, co := range operatorList.Items {
			available := false
			for _, condition := range co.Status.Conditions {
				if condition.Type == configapi.OperatorAvailable {
					if condition.Status == configapi.ConditionTrue {
						available = true
						break
					} else {
						return false, nil
					}
				}
			}
			if !available {
				return false, nil
			}
		}
		return true, nil
	}

	_, err = clientwatch.UntilWithSync(ctx, listWatcher, &configapi.ClusterOperator{}, nil, clusterOperatorsAreAvailable)
	return err
}

func waitForServiceLoadBalancerAddress(client kubeclient.Interface, namespace, name string) (string, error) {
	var serviceAddress string

	ctx, cancel := context.WithTimeout(context.Background(), serviceLoadBalancerTimeout)
	defer cancel()
	listWatcher := cache.NewListWatchFromClient(client.CoreV1().RESTClient(), "services", namespace, fields.OneTermEqualSelector("metadata.name", name))

	serviceReady := func(event watch.Event) (bool, error) {
		svc, ok := event.Object.(*corev1.Service)
		if !ok {
			return false, fmt.Errorf("unexpected object type")
		}
		if svc.Name != name {
			return false, fmt.Errorf("unexpected service name: %s", svc.Name)
		}

		if len(svc.Status.LoadBalancer.Ingress) < 1 {
			return false, nil
		}

		if svc.Status.LoadBalancer.Ingress[0].Hostname != "" {
			serviceAddress = svc.Status.LoadBalancer.Ingress[0].Hostname
			return true, nil
		} else if svc.Status.LoadBalancer.Ingress[0].IP != "" {
			serviceAddress = svc.Status.LoadBalancer.Ingress[0].IP
			return true, nil
		}

		return false, fmt.Errorf("service's status indicates that it is ready, but neither hostname nor IP are set")
	}

	_, err := clientwatch.UntilWithSync(ctx, listWatcher, &corev1.Service{}, nil, serviceReady)

	return serviceAddress, errors.Wrap(err, "failed getting address for Service")
}
