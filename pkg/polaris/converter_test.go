package polaris

import (
	"os"
	"testing"

	"github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConverter_Convert(t *testing.T) {
	// FIXME Deterministic assert!
	t.Skip("Fix me - the assert is not deterministic")
	file, err := os.Open("testdata/polaris-report.json")
	require.NoError(t, err)
	defer func() {
		_ = file.Close()
	}()

	reports, err := NewConverter().Convert(file)
	require.NoError(t, err)
	assert.Equal(t, []v1alpha1.ConfigAudit{
		{
			Scanner: v1alpha1.Scanner{
				Name:    "Polaris",
				Vendor:  "Fairwinds",
				Version: "latest",
			},
			PodChecks: []v1alpha1.Check{
				{
					ID:       "hostIPCSet",
					Message:  "Host IPC is not configured",
					Success:  true,
					Severity: "error",
					Category: "Security",
				},
				{
					ID:       "hostNetworkSet",
					Message:  "Host network is not configured",
					Success:  true,
					Severity: "warning",
					Category: "Networking",
				},
			},
			ContainerChecks: map[string][]v1alpha1.Check{
				"db": {
					{
						ID:       "cpuLimitsMissing",
						Message:  "CPU limits are set",
						Success:  true,
						Severity: "warning",
						Category: "Resources",
					},
					{
						ID:       "cpuRequestsMissing",
						Message:  "CPU requests are set",
						Success:  true,
						Severity: "warning",
						Category: "Resources",
					},
				},
			},
		},
	}, reports)
}
