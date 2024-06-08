package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/spf13/cobra"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewInitCmd(buildInfo starboard.BuildInfo, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "install",
		Aliases: []string{"init"},
		Short:   "Create Kubernetes resources used by Starboard",
		Long: `Create all the resources used by Starboard. It will create the following in your
Kubernetes cluster:

 - CustomResourceDefinition objects:
   - "vulnerabilityreports.khulnasoft.github.io"
   - "clustervulnerabilityreports.khulnasoft.github.io"
   - "configauditreports.khulnasoft.github.io"
   - "clusterconfigauditreports.khulnasoft.github.io"
   - "ciskubebenchreports.khulnasoft.github.io"
   - "kubehunterreports.khulnasoft.github.io"
 - RBAC objects:
   - The "starboard" ClusterRole
   - The "starboard" ClusterRoleBinding
 - The "starboard" namespace with the following objects:
   - The "starboard" service account
   - The "starboard" ConfigMap
   - The "starboard" secret
   - The "starboard-trivy-config" ConfigMap
   - The "starboard-polaris-config" ConfigMap

The "starboard" ConfigMap and the "starboard" secret contain the default
config parameters. However this can be modified to change the behaviour
of the scanners.

All resources created by this command can be removed from the cluster using
the "uninstall" command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeConfig, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			apiExtensionsClientset, err := apiextensionsv1.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			scheme := starboard.NewScheme()
			kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
			if err != nil {
				return err
			}
			configManager := starboard.NewConfigManager(kubeClientset, starboard.NamespaceName)
			installer := NewInstaller(buildInfo, kubeClientset, apiExtensionsClientset, kubeClient, configManager)
			err = installer.Install(context.Background())
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout)
			fmt.Fprintf(os.Stdout, starboard.Banner)
			return nil
		},
	}
	return cmd
}
