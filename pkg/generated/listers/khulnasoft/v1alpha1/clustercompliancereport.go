// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ClusterComplianceReportLister helps list ClusterComplianceReports.
// All objects returned here must be treated as read-only.
type ClusterComplianceReportLister interface {
	// List lists all ClusterComplianceReports in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.ClusterComplianceReport, err error)
	// ClusterComplianceReports returns an object that can list and get ClusterComplianceReports.
	ClusterComplianceReports(namespace string) ClusterComplianceReportNamespaceLister
	ClusterComplianceReportListerExpansion
}

// clusterComplianceReportLister implements the ClusterComplianceReportLister interface.
type clusterComplianceReportLister struct {
	indexer cache.Indexer
}

// NewClusterComplianceReportLister returns a new ClusterComplianceReportLister.
func NewClusterComplianceReportLister(indexer cache.Indexer) ClusterComplianceReportLister {
	return &clusterComplianceReportLister{indexer: indexer}
}

// List lists all ClusterComplianceReports in the indexer.
func (s *clusterComplianceReportLister) List(selector labels.Selector) (ret []*v1alpha1.ClusterComplianceReport, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.ClusterComplianceReport))
	})
	return ret, err
}

// ClusterComplianceReports returns an object that can list and get ClusterComplianceReports.
func (s *clusterComplianceReportLister) ClusterComplianceReports(namespace string) ClusterComplianceReportNamespaceLister {
	return clusterComplianceReportNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ClusterComplianceReportNamespaceLister helps list and get ClusterComplianceReports.
// All objects returned here must be treated as read-only.
type ClusterComplianceReportNamespaceLister interface {
	// List lists all ClusterComplianceReports in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.ClusterComplianceReport, err error)
	// Get retrieves the ClusterComplianceReport from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.ClusterComplianceReport, error)
	ClusterComplianceReportNamespaceListerExpansion
}

// clusterComplianceReportNamespaceLister implements the ClusterComplianceReportNamespaceLister
// interface.
type clusterComplianceReportNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ClusterComplianceReports in the indexer for a given namespace.
func (s clusterComplianceReportNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.ClusterComplianceReport, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.ClusterComplianceReport))
	})
	return ret, err
}

// Get retrieves the ClusterComplianceReport from the indexer for a given namespace and name.
func (s clusterComplianceReportNamespaceLister) Get(name string) (*v1alpha1.ClusterComplianceReport, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("clustercompliancereport"), name)
	}
	return obj.(*v1alpha1.ClusterComplianceReport), nil
}
