package cmd

import (
	"errors"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/khulnasoft/starboard/pkg/kube"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func SetGlobalFlags(cf *genericclioptions.ConfigFlags, cmd *cobra.Command) {
	cf.AddFlags(cmd.Flags())
	for _, c := range cmd.Commands() {
		SetGlobalFlags(cf, c)
	}
}

func WorkloadFromArgs(mapper meta.RESTMapper, namespace string, args []string) (workload kube.Object, gvk schema.GroupVersionKind, err error) {
	if len(args) < 1 {
		err = errors.New("required workload kind and name not specified")
		return
	}

	var resource, resourceName string
	parts := strings.SplitN(args[0], "/", 2)
	if len(parts) == 1 {
		resource = "pods"
		resourceName = parts[0]
	} else {
		resource = parts[0]
		resourceName = parts[1]
	}

	_, gvk, err = kube.GVRForResource(mapper, resource)
	if err != nil {
		return
	}
	if "" == resourceName {
		err = errors.New("required workload name is blank")
		return
	}
	workload = kube.Object{
		Namespace: namespace,
		Kind:      kube.Kind(gvk.Kind),
		Name:      resourceName,
	}
	return
}

func GetScheme() *runtime.Scheme {
	return scheme.Scheme
}

const (
	scanJobTimeoutFlagName = "scan-job-timeout"
	deleteScanJobFlagName  = "delete-scan-job"
)

func registerScannerOpts(cmd *cobra.Command) {
	cmd.Flags().Duration(scanJobTimeoutFlagName, time.Duration(0),
		"The length of time to wait before giving up on a scan job. Non-zero values should contain a"+
			" corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout the scan job.")
	cmd.Flags().Bool(deleteScanJobFlagName, true, "If true, delete a scan job either complete or failed")
}

func getScannerOpts(cmd *cobra.Command) (opts kube.ScannerOpts, err error) {
	opts.ScanJobTimeout, err = cmd.Flags().GetDuration(scanJobTimeoutFlagName)
	if err != nil {
		return
	}
	opts.DeleteScanJob, err = cmd.Flags().GetBool(deleteScanJobFlagName)
	if err != nil {
		return
	}
	return
}
