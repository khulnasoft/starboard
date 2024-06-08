package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"

	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/starboard/pkg/plugin/khulnasoft/client"
	"github.com/khulnasoft/starboard/pkg/plugin/khulnasoft/scanner/api"
	"github.com/khulnasoft/starboard/pkg/plugin/khulnasoft/scanner/cli"
	"github.com/spf13/cobra"
)

const (
	versionFlag  = "version"
	hostFlag     = "host"
	userFlag     = "user"
	passwordFlag = "password"
	registryFlag = "registry"
	commandFlag  = "command"
)

// main is the entrypoint of the executable command used by Khulnasoft vulnerabilityreport.Plugin.
func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %s", err.Error())
	}
}

func run() error {
	opt := cli.Options{}

	rootCmd := &cobra.Command{
		Use:           "scanner",
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := scan(opt, args[0])
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(report)
		},
	}

	rootCmd.Flags().StringVarP(&opt.Version, versionFlag, "V", "", "Version of Khulnasoft")
	rootCmd.Flags().StringVarP(&opt.BaseURL, hostFlag, "H", "", "Khulnasoft management console address (required)")
	rootCmd.Flags().StringVarP(&opt.Credentials.Username, userFlag, "U", "", "Khulnasoft management console username (required)")
	rootCmd.Flags().StringVarP(&opt.Credentials.Password, passwordFlag, "P", "", "Khulnasoft management console password (required)")
	rootCmd.Flags().StringVarP(&opt.RegistryName, registryFlag, "R", "", "Registry name from Khulnasoft management console")
	rootCmd.Flags().StringVarP(&opt.Command, commandFlag, "C", "image", "Command mode to use for scanner eg image/fs")

	_ = rootCmd.MarkFlagRequired(versionFlag)
	_ = rootCmd.MarkFlagRequired(hostFlag)
	_ = rootCmd.MarkFlagRequired(userFlag)
	_ = rootCmd.MarkFlagRequired(passwordFlag)

	return rootCmd.Execute()
}

// scan scans the specified image reference. Firstly, attempt to download a vulnerability
// report with Khulnasoft REST API call. If the report is not found, execute the `scannercli scan` command.
func scan(opt cli.Options, imageRef string) (report v1alpha1.VulnerabilityReportData, err error) {
	clientset, err := client.NewClient(opt.BaseURL, client.Authorization{
		Basic: &opt.Credentials,
	})
	if err != nil {
		return
	}

	report, err = api.NewScanner(opt, clientset).Scan(imageRef)
	if err == nil {
		return
	}
	if !errors.Is(err, client.ErrNotFound) {
		return
	}
	report, err = cli.NewScanner(opt).Scan(imageRef)
	if err != nil {
		return
	}
	return
}
