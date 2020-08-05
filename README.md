# Hypershift Installer

## Overview
The hypershift installer is a program for running OpenShift 4.x in a hyperscale manner with many control planes hosted on a central management cluster. 

## Getting Started

### Build and run the installer

* Install an Openshift 4.x cluster on AWS/GCP/Azure using the traditional installer
* Obtain the latest `ibm-roks` binary from [openshift/ibm-roks-toolkit releases](https://github.com/openshift/ibm-roks-toolkit/releases)
  that corresponds to the release of the cluster that you are creating (4.3, 4.4, 4.5, etc).
* Ensure the `ibm-roks` binary is in your path.
* Run `make` on this repository
* Setup your KUBECONFIG to point to the admin kubeconfig of your current AWS cluster
  (ie. `export KUBECONFIG=${INSTALL_DIR}/auth/kubeconfig`)
* Run `./bin/hypershift-installer create install-config NAME` to create a new install-config
  for your child cluster. The `install-config.yaml` will be placed in your current directory.
  The `NAME` parameter must be unique for the parent cluster. It will be used by the `create cluster`
  command to create a namespace on your existing cluster and place all control plane components in it.
* Run `./bin/hypershift-installer create cluster` command to install a new child cluster on your
  existing cluster.  
  This command will create a directory named `install-files` under the current directory
  that contains manifests and PKI resources generated for the child cluster.
  The command will create the necessary resources on the parent cluster
  to support the child cluster, including:
  - A router shard (IngressController) to support routing to the child cluster
  - Services of load balancer type for API, OAuth, and VPN
  - Worker machine instances for your new cluster

### Uninstalling the child cluster
* Setup your KUBECONFIG to point to the management cluster
* Run `./bin/hypershift-installer destroy cluster NAME` where NAME is the name you gave your
  cluster when creating the `install-config.yaml`.
