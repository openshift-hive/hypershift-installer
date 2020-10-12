package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/openshift-hive/hypershift-installer/pkg/installer"
)

var (
	rootOpts struct {
		logLevel string
	}
)

func main() {
	rootCmd := newRootCmd()

	if err := rootCmd.Execute(); err != nil {
		log.WithError(err).Fatal("failed to run command")
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:              "hypershift-installer",
		Short:            "An implementation of the Hypershift pattern",
		PersistentPreRun: runRootCmd,
	}
	cmd.PersistentFlags().StringVar(&rootOpts.logLevel, "log-level", "info", "Log verbosity level.")
	cmd.AddCommand(newCreateCommand())
	cmd.AddCommand(newDestroyCommand())
	return cmd
}

func runRootCmd(cmd *cobra.Command, args []string) {
	lvl, err := log.ParseLevel(rootOpts.logLevel)
	if err != nil {
		log.WithError(err).Fatal("failed to parse log-level")
	}
	log.SetLevel(lvl)
}

func newCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create installer artifacts",
	}
	cmd.AddCommand(newCreateClusterCommand())
	cmd.AddCommand(newCreateInstallConfigCommand())
	return cmd
}

func newDestroyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Destroy installer artifacts",
	}
	cmd.AddCommand(newDestroyClusterCommand())
	return cmd
}

func newCreateInstallConfigCommand() *cobra.Command {
	opts := installer.CreateInstallConfigOpts{
		Directory: "",
		Local:     false,
	}
	cmd := &cobra.Command{
		Use:   "install-config NAME",
		Short: "Create install-config using defaults from an existing parent cluster",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 || len(args[0]) == 0 {
				log.Fatalf("You must specify the name of the cluster you want to install")
			}
			opts.Name = args[0]
			if err := opts.Run(); err != nil {
				log.WithError(err).Fatalf("Failed to create install-config")
			}
		},
	}
	cmd.Flags().StringVarP(&opts.Directory, "dir", "o", opts.Directory, "Specify the directory where install assets should be placed. Defaults to current directory.")
	cmd.Flags().StringVar(&opts.PullSecretFile, "pull-secret", opts.PullSecretFile, "Specify a file containing the pull secret to use.")
	cmd.Flags().StringVar(&opts.SSHKeyFile, "ssh-key", opts.SSHKeyFile, "Specify a public SSH key to use for cluster machines.")
	cmd.Flags().BoolVar(&opts.Local, "local", opts.Local, "If true, a cluster will not be contacted.")
	return cmd
}

func newCreateClusterCommand() *cobra.Command {
	opts := installer.CreateClusterOpts{
		Wait:   true,
		DryRun: false,
	}
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Creates the necessary infrastructure and installs a hypershift instance on an existing OCP 4 cluster",
		Run: func(cmd *cobra.Command, args []string) {
			if err := opts.Run(); err != nil {
				log.WithError(err).Fatalf("Failed to install cluster")
			}
		},
	}
	cmd.Flags().StringVar(&opts.ReleaseImage, "release-image", opts.ReleaseImage, "[optional] Specify the release image to use for the new cluster. Defaults to same as parent cluster.")
	cmd.Flags().StringVar(&opts.AMI, "ami", "", "[optional] Specify the AMI ID to use for worker machinesets.")
	cmd.Flags().StringVar(&opts.Directory, "dir", opts.Directory, "Specify the path of the working directory for the install (location of install-config.yaml)")
	cmd.Flags().BoolVar(&opts.Wait, "wait", opts.Wait, "Waits for cluster to be available before command ends, fails with an error if cluster does not come up within a given amount of time.")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", opts.DryRun, "Generates manifests and PKI artifacts for cluster but does not create one. Requires that a release image be specified.")

	return cmd
}

func newDestroyClusterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster NAME",
		Short: "Removes artifacts from an existing hypershift instance on an parent cluster",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 || len(args[0]) == 0 {
				log.Fatalf("You must specify the name of the cluster you want to uninstall")
			}
			name := args[0]
			if err := installer.UninstallCluster(name); err != nil {
				log.WithError(err).Fatalf("Failed to uninstall cluster")
			}
		},
	}
	return cmd

}
