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

	rootCmd.AddCommand(newInstallCommand())
	rootCmd.AddCommand(newUninstallCommand())

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

	return cmd
}

func runRootCmd(cmd *cobra.Command, args []string) {
	lvl, err := log.ParseLevel(rootOpts.logLevel)
	if err != nil {
		log.WithError(err).Fatal("failed to parse log-level")
	}
	log.SetLevel(lvl)
}

func newInstallCommand() *cobra.Command {
	releaseImage := ""
	dhParamsFile := ""
	waitForClusterReady := true

	cmd := &cobra.Command{
		Use:   "install NAME",
		Short: "Creates the necessary infrastructure and installs a hypershift instance on an existing OCP 4 cluster running on AWS",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				log.Fatalf("You must specify the name of the cluster you want to install")
			}
			name := args[0]
			if len(name) == 0 {
				log.Fatalf("You must specify the name of the cluster you want to install")
			}

			if err := installer.InstallCluster(name, releaseImage, dhParamsFile, waitForClusterReady); err != nil {
				log.WithError(err).Fatalf("Failed to install cluster")
			}
		},
	}
	cmd.Flags().StringVar(&releaseImage, "release-image", "", "[optional] Specify the release image to use for the new cluster. Defaults to same as parent cluster.")
	cmd.Flags().StringVar(&dhParamsFile, "dh-params", "", "[optional][dev-only] Specifies an existing file with DH params for the VPN so it doesn't get re-generated.")
	cmd.Flags().BoolVar(&waitForClusterReady, "wait-for-cluster-ready", waitForClusterReady, "Waits for cluster to be available before command ends, fails with an error if cluster does not come up within a given amount of time.")

	return cmd
}

func newUninstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall NAME",
		Short: "Removes artifacts from an existing hypershift instance on an AWS cluster",
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
