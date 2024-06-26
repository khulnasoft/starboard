// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/khulnasoft/starboard/pkg/generated/clientset/versioned/typed/khulnasoft/v1alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeKhulnasoftV1alpha1 struct {
	*testing.Fake
}

func (c *FakeKhulnasoftV1alpha1) CISKubeBenchReports() v1alpha1.CISKubeBenchReportInterface {
	return &FakeCISKubeBenchReports{c}
}

func (c *FakeKhulnasoftV1alpha1) ClusterComplianceDetailReports(namespace string) v1alpha1.ClusterComplianceDetailReportInterface {
	return &FakeClusterComplianceDetailReports{c, namespace}
}

func (c *FakeKhulnasoftV1alpha1) ClusterComplianceReports(namespace string) v1alpha1.ClusterComplianceReportInterface {
	return &FakeClusterComplianceReports{c, namespace}
}

func (c *FakeKhulnasoftV1alpha1) ClusterConfigAuditReports() v1alpha1.ClusterConfigAuditReportInterface {
	return &FakeClusterConfigAuditReports{c}
}

func (c *FakeKhulnasoftV1alpha1) ClusterVulnerabilityReports() v1alpha1.ClusterVulnerabilityReportInterface {
	return &FakeClusterVulnerabilityReports{c}
}

func (c *FakeKhulnasoftV1alpha1) ConfigAuditReports(namespace string) v1alpha1.ConfigAuditReportInterface {
	return &FakeConfigAuditReports{c, namespace}
}

func (c *FakeKhulnasoftV1alpha1) KubeHunterReports() v1alpha1.KubeHunterReportInterface {
	return &FakeKubeHunterReports{c}
}

func (c *FakeKhulnasoftV1alpha1) VulnerabilityReports(namespace string) v1alpha1.VulnerabilityReportInterface {
	return &FakeVulnerabilityReports{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeKhulnasoftV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
