package crd

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/apimachinery/pkg/labels"

	starboard "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	clientset "github.com/khulnasoft/starboard/pkg/generated/clientset/versioned"
	"github.com/khulnasoft/starboard/pkg/kube"
	"github.com/khulnasoft/starboard/pkg/polaris"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
)

type ReadWriter struct {
	scheme *runtime.Scheme
	client clientset.Interface
}

func NewReadWriter(scheme *runtime.Scheme, client clientset.Interface) polaris.ReadWriter {
	return &ReadWriter{
		scheme: scheme,
		client: client,
	}
}

func (w *ReadWriter) Write(ctx context.Context, report starboard.ConfigAudit, owner metav1.Object) (err error) {
	var kind string
	kind, err = kube.KindForObject(owner, w.scheme)
	if err != nil {
		return
	}
	namespace := owner.GetNamespace()
	name := fmt.Sprintf("%s.%s", strings.ToLower(kind), owner.GetName())

	existingCR, err := w.client.KhulnasoftV1alpha1().ConfigAuditReports(namespace).Get(ctx, name, metav1.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating config audit report: %s/%s", namespace, name)
		deepCopy := existingCR.DeepCopy()
		deepCopy.Report = report
		_, err = w.client.KhulnasoftV1alpha1().ConfigAuditReports(namespace).Update(ctx, deepCopy, metav1.UpdateOptions{})
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating config audit report: %s/%s", namespace, name)
		report := &starboard.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: owner.GetNamespace(),
				Labels: labels.Set{
					kube.LabelResourceKind:      kind,
					kube.LabelResourceName:      owner.GetName(),
					kube.LabelResourceNamespace: owner.GetNamespace(),
				},
			},
			Report: report,
		}
		err = kube.SetOwnerReference(owner, report, w.scheme)
		if err != nil {
			return
		}
		_, err = w.client.KhulnasoftV1alpha1().ConfigAuditReports(namespace).
			Create(ctx, report, metav1.CreateOptions{})
		return
	}
	return
}

func (w *ReadWriter) WriteAll(ctx context.Context, reports []starboard.ConfigAudit, owner metav1.Object) (err error) {
	for _, report := range reports {
		err = w.Write(ctx, report, owner)
	}
	return
}

func (w *ReadWriter) Read(ctx context.Context, workload kube.Object) (starboard.ConfigAuditReport, error) {
	list, err := w.client.KhulnasoftV1alpha1().ConfigAuditReports(workload.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{
			kube.LabelResourceKind: string(workload.Kind),
			kube.LabelResourceName: workload.Name,
		}.String(),
	})
	if err != nil {
		return starboard.ConfigAuditReport{}, err
	}
	// Only one config audit per specific workload exists on the cluster
	if len(list.Items) > 0 {
		return list.Items[0], nil
	}
	return starboard.ConfigAuditReport{}, nil
}
