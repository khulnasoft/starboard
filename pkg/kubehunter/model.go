package kubehunter

import (
	"encoding/json"
	sec "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"io"
)

func OutputFrom(reader io.Reader) (report sec.KubeHunterOutput, err error) {
	report.Scanner = sec.Scanner{
		Name:    "kube-hunter",
		Vendor:  "Khulnasoft Security",
		Version: kubeHunterVersion,
	}
	err = json.NewDecoder(reader).Decode(&report)
	return
}
