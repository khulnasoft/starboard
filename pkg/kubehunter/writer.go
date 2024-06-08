package kubehunter

import (
	"context"
	"errors"
	"strings"

	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/starboard/pkg/generated/clientset/versioned"
	"github.com/khulnasoft/starboard/pkg/starboard"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Writer interface {
	Write(ctx context.Context, report v1alpha1.KubeHunterReportData, cluster string) error
}

type writer struct {
	clientset versioned.Interface
}

func NewWriter(clientset versioned.Interface) Writer {
	return &writer{
		clientset: clientset,
	}
}

func (w *writer) Write(ctx context.Context, report v1alpha1.KubeHunterReportData, cluster string) error {
	if strings.TrimSpace(cluster) == "" {
		return errors.New("cluster name must not be blank")
	}
	_, err := w.clientset.KhulnasoftV1alpha1().KubeHunterReports().Create(ctx, &v1alpha1.KubeHunterReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: cluster,
			Labels: map[string]string{
				starboard.LabelResourceKind: "Cluster",
				starboard.LabelResourceName: cluster,
			},
		},
		Report: report,
	}, metav1.CreateOptions{})
	if err != nil && apierrors.IsAlreadyExists(err) {
		found, err := w.clientset.KhulnasoftV1alpha1().KubeHunterReports().Get(ctx, cluster, metav1.GetOptions{})
		if err != nil {
			return err
		}
		deepCopy := found.DeepCopy()
		deepCopy.Report = report
		_, err = w.clientset.KhulnasoftV1alpha1().KubeHunterReports().Update(ctx, deepCopy, metav1.UpdateOptions{})
		return err
	}
	return err
}
