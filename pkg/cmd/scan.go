package cmd

import (
	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func NewScanCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:     "scan",
		Aliases: []string{"generate"},
		Short:   "Manage security weakness identification tools",
	}
	scanCmd.AddCommand(NewScanConfigAuditReportsCmd(buildInfo, cf))
	scanCmd.AddCommand(NewScanKubeBenchReportsCmd(cf))
	scanCmd.AddCommand(NewScanKubeHunterReportsCmd(cf))
	scanCmd.AddCommand(NewScanVulnerabilityReportsCmd(buildInfo, cf))

	return scanCmd
}
