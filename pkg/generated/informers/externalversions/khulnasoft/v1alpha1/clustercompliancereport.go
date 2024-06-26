// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	khulnasoftv1alpha1 "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	versioned "github.com/khulnasoft/starboard/pkg/generated/clientset/versioned"
	internalinterfaces "github.com/khulnasoft/starboard/pkg/generated/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/khulnasoft/starboard/pkg/generated/listers/khulnasoft/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ClusterComplianceReportInformer provides access to a shared informer and lister for
// ClusterComplianceReports.
type ClusterComplianceReportInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.ClusterComplianceReportLister
}

type clusterComplianceReportInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewClusterComplianceReportInformer constructs a new informer for ClusterComplianceReport type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewClusterComplianceReportInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredClusterComplianceReportInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredClusterComplianceReportInformer constructs a new informer for ClusterComplianceReport type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredClusterComplianceReportInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KhulnasoftV1alpha1().ClusterComplianceReports(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KhulnasoftV1alpha1().ClusterComplianceReports(namespace).Watch(context.TODO(), options)
			},
		},
		&khulnasoftv1alpha1.ClusterComplianceReport{},
		resyncPeriod,
		indexers,
	)
}

func (f *clusterComplianceReportInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredClusterComplianceReportInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *clusterComplianceReportInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&khulnasoftv1alpha1.ClusterComplianceReport{}, f.defaultInformer)
}

func (f *clusterComplianceReportInformer) Lister() v1alpha1.ClusterComplianceReportLister {
	return v1alpha1.NewClusterComplianceReportLister(f.Informer().GetIndexer())
}
