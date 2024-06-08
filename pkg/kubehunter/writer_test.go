package kubehunter_test

import (
	"context"
	"testing"

	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/starboard/pkg/generated/clientset/versioned/fake"
	"github.com/khulnasoft/starboard/pkg/kubehunter"
	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWriter_Write(t *testing.T) {

	t.Run("Should create KubeHunterReport", func(t *testing.T) {
		clientset := fake.NewSimpleClientset()

		writer := kubehunter.NewWriter(clientset)
		err := writer.Write(context.TODO(), v1alpha1.KubeHunterReportData{
			Summary: v1alpha1.KubeHunterSummary{
				HighCount: 7,
			},
		}, "my-cluster")
		require.NoError(t, err)

		list, err := clientset.KhulnasoftV1alpha1().KubeHunterReports().List(context.TODO(), metav1.ListOptions{})
		require.NoError(t, err)

		reports := map[string]v1alpha1.KubeHunterReport{}
		for _, item := range list.Items {
			reports[item.Name] = item
		}
		assert.Equal(t, map[string]v1alpha1.KubeHunterReport{
			"my-cluster": {
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-cluster",
					Labels: map[string]string{
						starboard.LabelResourceKind: "Cluster",
						starboard.LabelResourceName: "my-cluster",
					},
				},
				Report: v1alpha1.KubeHunterReportData{
					Summary: v1alpha1.KubeHunterSummary{
						HighCount: 7,
					},
				},
			},
		}, reports)
	})

	t.Run("Should update KubeHunterReport", func(t *testing.T) {
		clientset := fake.NewSimpleClientset(&v1alpha1.KubeHunterReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "my-cluster",
				Labels: map[string]string{
					starboard.LabelResourceKind: "Cluster",
					starboard.LabelResourceName: "my-cluster",
				},
			},
			Report: v1alpha1.KubeHunterReportData{
				Summary: v1alpha1.KubeHunterSummary{
					HighCount: 1,
				},
			},
		})

		writer := kubehunter.NewWriter(clientset)
		err := writer.Write(context.TODO(), v1alpha1.KubeHunterReportData{
			Summary: v1alpha1.KubeHunterSummary{
				HighCount: 3,
			},
		}, "my-cluster")
		require.NoError(t, err)

		list, err := clientset.KhulnasoftV1alpha1().KubeHunterReports().List(context.TODO(), metav1.ListOptions{})
		require.NoError(t, err)

		reports := map[string]v1alpha1.KubeHunterReport{}
		for _, item := range list.Items {
			reports[item.Name] = item
		}
		assert.Equal(t, map[string]v1alpha1.KubeHunterReport{
			"my-cluster": {
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-cluster",
					Labels: map[string]string{
						starboard.LabelResourceKind: "Cluster",
						starboard.LabelResourceName: "my-cluster",
					},
				},
				Report: v1alpha1.KubeHunterReportData{
					Summary: v1alpha1.KubeHunterSummary{
						HighCount: 3,
					},
				},
			},
		}, reports)
	})

}
