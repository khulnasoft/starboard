package cmd

import (
	"io"

	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewGetCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Get security reports",
	}
	getCmd.AddCommand(NewGetVulnerabilityReportsCmd(buildInfo.Executable, cf, outWriter))
	getCmd.AddCommand(NewGetConfigAuditReportsCmd(buildInfo.Executable, cf, outWriter))
	getCmd.AddCommand(NewGetClusterComplianceReportsCmd(buildInfo.Executable, cf, outWriter))
	getCmd.PersistentFlags().StringP("output", "o", "", "Output format. One of yaml|json")

	return getCmd
}
