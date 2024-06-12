package trivy

import (
	sec "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
)

type ScanReport struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string       `json:"VulnerabilityID"`
	PkgName          string       `json:"PkgName"`
	InstalledVersion string       `json:"InstalledVersion"`
	FixedVersion     string       `json:"FixedVersion"`
	Title            string       `json:"Title"`
	Description      string       `json:"Description"`
	Severity         sec.Severity `json:"Severity"`
	LayerID          string       `json:"LayerID"`
	References       []string     `json:"References"`
}
