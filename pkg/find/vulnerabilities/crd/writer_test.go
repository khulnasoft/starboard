package crd_test

import (
	"context"
	"testing"

	"github.com/khulnasoft/starboard/pkg/find/vulnerabilities/crd"

	"github.com/khulnasoft/starboard/pkg/cmd"

	"github.com/khulnasoft/starboard/pkg/find/vulnerabilities"

	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/starboard/pkg/generated/clientset/versioned/fake"
	"github.com/khulnasoft/starboard/pkg/kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	vulnerabilityReport01 = v1alpha1.VulnerabilityScanResult{
		Vulnerabilities: []v1alpha1.Vulnerability{
			{VulnerabilityID: "CVE-2020-1832"},
		},
	}
	vulnerabilityReport02 = v1alpha1.VulnerabilityScanResult{
		Vulnerabilities: []v1alpha1.Vulnerability{
			{VulnerabilityID: "CVE-2019-8211"},
		},
	}
)

func TestReadWriter_Read(t *testing.T) {
	clientset := fake.NewSimpleClientset(&v1alpha1.VulnerabilityReport{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Vulnerability",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "my-namespace",
			Name:      "my-deploy-my-container-01",
			Labels: map[string]string{
				kube.LabelResourceKind:      string(kube.KindDeployment),
				kube.LabelResourceName:      "my-deploy",
				kube.LabelResourceNamespace: "my-namespace",
				kube.LabelContainerName:     "my-container-01",
			},
		},
		Report: vulnerabilityReport01,
	}, &v1alpha1.VulnerabilityReport{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Vulnerability",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "my-namespace",
			Name:      "my-deploy-my-container-02",
			Labels: map[string]string{
				kube.LabelResourceKind:      string(kube.KindDeployment),
				kube.LabelResourceName:      "my-deploy",
				kube.LabelResourceNamespace: "my-namespace",
				kube.LabelContainerName:     "my-container-02",
			},
		},
		Report: vulnerabilityReport02,
	}, &v1alpha1.VulnerabilityReport{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Vulnerability",
			APIVersion: "v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "my-namespace",
			Name:      "my-sts",
			Labels: map[string]string{
				kube.LabelResourceKind:      string(kube.KindStatefulSet),
				kube.LabelResourceName:      "my-sts",
				kube.LabelResourceNamespace: "my-namespace",
				kube.LabelContainerName:     "my-sts-container",
			},
		},
		Report: v1alpha1.VulnerabilityScanResult{},
	})

	reports, err := crd.NewReadWriter(cmd.GetScheme(), clientset).Read(context.TODO(), kube.Object{
		Kind:      kube.KindDeployment,
		Name:      "my-deploy",
		Namespace: "my-namespace",
	})
	require.NoError(t, err)

	assert.Equal(t, vulnerabilities.WorkloadVulnerabilities{
		"my-container-01": vulnerabilityReport01,
		"my-container-02": vulnerabilityReport02,
	}, reports)
}
