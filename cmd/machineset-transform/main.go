package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/openshift-hive/hypershift-installer/pkg/machineset"
)

func main() {
	transformCmd := newTransformCmd()

	if err := transformCmd.Execute(); err != nil {
		log.WithError(err).Fatal("error")
	}
}

func newTransformCmd() *cobra.Command {
	machineSetTransform := machineset.NewTransformCmd()
	cmd := &cobra.Command{
		Use:   "machineset-transform",
		Short: "Machineset manifest transformer for Hypershift",
		Run: func(cmd *cobra.Command, args []string) {
			if err := machineSetTransform.Validate(); err != nil {
				fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
				cmd.Usage()
				os.Exit(1)
			}
			if err := machineSetTransform.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	machineSetTransform.BindFlags(cmd.Flags())
	return cmd
}
