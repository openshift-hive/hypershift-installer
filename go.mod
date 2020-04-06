module github.com/openshift-hive/hypershift-installer

replace (
	github.com/apcera/gssapi => github.com/openshift/gssapi v0.0.0-20161010215902-5fb4217df13b
	github.com/containers/image => github.com/openshift/containers-image v0.0.0-20190130162827-4bc6d24282b1
	github.com/docker/docker => github.com/docker/docker v0.0.0-20180612054059-a9fbbdc8dd87
	github.com/openshift/oc => github.com/openshift/oc v0.0.0-alpha.0.0.20191024120018-118066a57f62
	k8s.io/api => k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20190918161926-8f644eb6e783
	k8s.io/apimachinery => github.com/openshift/kubernetes-apimachinery v0.0.0-20190926190123-4ba2b154755f
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20190918160949-bfa5e2e684ad
	k8s.io/cli-runtime => github.com/openshift/kubernetes-cli-runtime v0.0.0-20190926190147-2354228a7b44
	k8s.io/client-go => github.com/openshift/kubernetes-client-go v0.0.0-20190926190130-2917f17b9089
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20190918163234-a9c1f33e9fb9
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.0.0-20190918163108-da9fdfce26bb
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
	k8s.io/component-base => k8s.io/component-base v0.0.0-20190918160511-547f6c5d7090
	k8s.io/cri-api => k8s.io/cri-api v0.0.0-20190828162817-608eb1dad4ac
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.0.0-20190918163402-db86a8c7bb21
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20190918161219-8c8f079fddc3
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.0.0-20190918162944-7a93a0ddadd8
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.0.0-20190918162534-de037b596c1e
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.0.0-20190918162820-3b5c1246eb18
	k8s.io/kubectl => github.com/openshift/kubernetes-kubectl v0.0.0-20190926190201-54079662af88
	k8s.io/kubelet => k8s.io/kubelet v0.0.0-20190918162654-250a1838aa2c
	k8s.io/kubernetes => github.com/openshift/kubernetes v1.16.0-beta.0.0.20190926205813-ab72ed558cb1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.0.0-20190918163543-cfa506e53441
	k8s.io/metrics => k8s.io/metrics v0.0.0-20190918162108-227c654b2546
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.0.0-20190918161442-d4c9c65c82af
)

go 1.13

require (
	github.com/apparentlymart/go-cidr v1.0.1
	github.com/aws/aws-sdk-go v1.30.0
	github.com/openshift/api v0.0.0-20200330134433-8e259f67fc55
	github.com/openshift/client-go v0.0.0-20200116152001-92a2713fa240
	github.com/openshift/hypershift-toolkit v0.0.0-20200328003509-09ef0f45e8ae
	github.com/sirupsen/logrus v1.5.0
	github.com/spf13/cobra v0.0.7
	golang.org/x/crypto v0.0.0-20200323165209-0ec3e9974c59
	k8s.io/api v0.18.0
	k8s.io/apimachinery v0.18.0
	k8s.io/cli-runtime v0.0.0
	k8s.io/client-go v0.17.1
	k8s.io/kubectl v0.0.0
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
)
