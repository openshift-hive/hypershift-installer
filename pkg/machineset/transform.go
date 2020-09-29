package machineset

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/scheme"

	flag "github.com/spf13/pflag"
)

type TransformCmd struct {
	SourceManifestDir string
	DestDir           string
	InfraID           string
	ClusterName       string
}

type ManifestTransformer interface {
	TransformManifest(sourcePath, destPath string) error
}

type TransformerProvider interface {
	CanHandle(platformType string) bool
	Transformer(sourceInfraID, destInfraID, clusterName string) ManifestTransformer
}

var (
	transformerProviders []TransformerProvider
)

func RegisterProvider(t TransformerProvider) {
	transformerProviders = append(transformerProviders, t)
}

func NewTransformCmd() *TransformCmd {
	return &TransformCmd{}
}

func (c *TransformCmd) BindFlags(flagSet *flag.FlagSet) {
	flagSet.StringVar(&c.SourceManifestDir, "source", "", "Manifests directory that contains machinesets to transform")
	flagSet.StringVar(&c.DestDir, "destination", "", "Destination directory for transformed manifests")
	flagSet.StringVar(&c.InfraID, "infra-id", "", "InfraID of target cluster")
	flagSet.StringVar(&c.ClusterName, "cluster-name", "", "Hypershift cluster name")
}

func (c *TransformCmd) Validate() error {
	if len(c.SourceManifestDir) == 0 || len(c.DestDir) == 0 {
		return fmt.Errorf("source and destination directories are required")
	}
	if len(c.InfraID) == 0 {
		return fmt.Errorf("infra-id is required")
	}
	if len(c.ClusterName) == 0 {
		return fmt.Errorf("cluster-name is required")
	}
	return nil
}

type infrastructure struct {
	infraID      string
	platformType string
}

func (c *TransformCmd) Run() error {
	infra, err := c.getInfra()
	if err != nil {
		return err
	}
	for _, t := range transformerProviders {
		if !t.CanHandle(infra.platformType) {
			continue
		}
		return c.transformManifests(t, infra)
	}
	return fmt.Errorf("unknown infrastructure type %s", infra.platformType)
}

var (
	infrastructureFilePath = []string{"manifests", "cluster-infrastructure-02-config.yml"}

	infraIDPath       = []string{"status", "infrastructureName"}
	infraPlatformPath = []string{"status", "platform"}
)

func (c *TransformCmd) getInfra() (*infrastructure, error) {
	filePath := filepath.Join(append([]string{c.SourceManifestDir}, infrastructureFilePath...)...)
	objBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot read infrastructure file (%s): %v", filePath, err)
	}
	u := &unstructured.Unstructured{}
	if _, _, err = scheme.Codecs.UniversalDecoder().Decode(objBytes, nil, u); err != nil {
		return nil, fmt.Errorf("cannot decode infrastructure: %v\nfile content: %s\n", err, string(objBytes))
	}
	obj := u.Object

	infraID, found, err := unstructured.NestedString(obj, infraIDPath...)
	if err != nil {
		return nil, fmt.Errorf("failed to get infrastructure ID from infrastructure: %v", err)
	}
	if !found {
		return nil, fmt.Errorf("infrastructure ID not found")
	}
	platformType, found, err := unstructured.NestedString(obj, infraPlatformPath...)
	if err != nil {
		return nil, fmt.Errorf("failed to get platform type from infrastructure(%s): %v", string(platformType), err)
	}
	if !found {
		return nil, fmt.Errorf("platform type not found in infrastructure")
	}
	infra := &infrastructure{
		infraID:      infraID,
		platformType: platformType,
	}
	return infra, nil
}

var (
	machinesetFilePattern = regexp.MustCompile("99_openshift-cluster-api_worker-machineset-.*")
)

func (c *TransformCmd) transformManifests(provider TransformerProvider, infra *infrastructure) error {
	sourceManifestFiles := []string{}
	manifestsDir := filepath.Join(c.SourceManifestDir, "openshift")
	allFiles, err := ioutil.ReadDir(manifestsDir)
	if err != nil {
		return fmt.Errorf("cannot list files in directory %s: %v", manifestsDir, err)
	}
	for _, file := range allFiles {
		if machinesetFilePattern.MatchString(file.Name()) {
			sourceManifestFiles = append(sourceManifestFiles, file.Name())
		}
	}
	if len(sourceManifestFiles) == 0 {
		return fmt.Errorf("did not find any source manifests in %s with files %s", manifestsDir, fileNames(allFiles))
	}
	manifestTransformer := provider.Transformer(infra.infraID, c.InfraID, c.ClusterName)
	for _, file := range sourceManifestFiles {
		if err := manifestTransformer.TransformManifest(filepath.Join(manifestsDir, file), filepath.Join(c.DestDir, file)); err != nil {
			return err
		}
	}
	return nil
}

func fileNames(infos []os.FileInfo) string {
	names := make([]string, len(infos))
	for i, info := range infos {
		names[i] = info.Name()
	}
	return strings.Join(names, ",")
}
