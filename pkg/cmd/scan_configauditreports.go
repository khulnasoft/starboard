package cmd

import (
	"context"

	"github.com/khulnasoft/starboard/pkg/configauditreport"
	"github.com/khulnasoft/starboard/pkg/kube"
	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	configAuditCmdShort = "Run a variety of checks to ensure that a given workload is configured using best practices"
)

func NewScanConfigAuditReportsCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configauditreports",
		Short: configAuditCmdShort,
		Args:  cobra.MaximumNArgs(1),
		RunE:  ScanConfigAuditReports(buildInfo, cf),
	}

	registerScannerOpts(cmd)

	return cmd
}

func ScanConfigAuditReports(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
		if err != nil {
			return err
		}
		mapper, err := cf.ToRESTMapper()
		if err != nil {
			return err
		}
		workload, _, err := WorkloadFromArgs(mapper, ns, args)
		if err != nil {
			return err
		}
		kubeConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		scheme := starboard.NewScheme()
		kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
		cm, err := kube.InitCompatibleMgr(kubeClient.RESTMapper())
		if err != nil {
			return err
		}
		scanner := configauditreport.NewScanner(buildInfo, kubeClient, cm)
		reportBuilder, err := scanner.Scan(ctx, workload)
		if err != nil {
			return err
		}
		objectResolver := kube.NewObjectResolver(kubeClient, cm)
		writer := configauditreport.NewReadWriter(&objectResolver)
		return reportBuilder.Write(ctx, writer)
	}
}
