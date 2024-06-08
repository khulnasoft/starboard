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

// ClusterConfigAuditReportInformer provides access to a shared informer and lister for
// ClusterConfigAuditReports.
type ClusterConfigAuditReportInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.ClusterConfigAuditReportLister
}

type clusterConfigAuditReportInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewClusterConfigAuditReportInformer constructs a new informer for ClusterConfigAuditReport type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewClusterConfigAuditReportInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredClusterConfigAuditReportInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredClusterConfigAuditReportInformer constructs a new informer for ClusterConfigAuditReport type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredClusterConfigAuditReportInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KhulnasoftV1alpha1().ClusterConfigAuditReports().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.KhulnasoftV1alpha1().ClusterConfigAuditReports().Watch(context.TODO(), options)
			},
		},
		&khulnasoftv1alpha1.ClusterConfigAuditReport{},
		resyncPeriod,
		indexers,
	)
}

func (f *clusterConfigAuditReportInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredClusterConfigAuditReportInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *clusterConfigAuditReportInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&khulnasoftv1alpha1.ClusterConfigAuditReport{}, f.defaultInformer)
}

func (f *clusterConfigAuditReportInformer) Lister() v1alpha1.ClusterConfigAuditReportLister {
	return v1alpha1.NewClusterConfigAuditReportLister(f.Informer().GetIndexer())
}
