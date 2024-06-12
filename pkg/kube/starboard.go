package kube

import (
	"time"
)

const (
	// NamespaceStarboard the name of the namespace in which Starboard stores its
	// configuration and runs scan Jobs.
	NamespaceStarboard = "starboard"
	// ServiceAccountStarboard the name of the ServiceAccount used to run scan Jobs.
	ServiceAccountStarboard = "starboard"
	// ConfigMapStarboard the name of the ConfigMap that stored configuration of
	// Starboard and the underlying scanners.
	ConfigMapStarboard = "starboard"
)

const (
	// TODO I'm wondering if we should rename starboard.resource.* labels to starboard.object.*
	// TODO In Kubernetes API terminology a resource is usually lowercase, plural word (e.g. pods) identifying a set of
	// TODO HTTP endpoints (paths) exposing the CRUD semantics of a certain object type in the system
	LabelResourceKind      = "starboard.resource.kind"
	LabelResourceName      = "starboard.resource.name"
	LabelResourceNamespace = "starboard.resource.namespace"

	LabelContainerName = "starboard.container.name"

	LabelScannerName   = "starboard.scanner.name"
	LabelScannerVendor = "starboard.scanner.vendor"
)

const (
	AnnotationContainerImages = "starboard.container-images"
)

// ScannerOpts holds configuration of the vulnerability Scanner.
type ScannerOpts struct {
	ScanJobTimeout time.Duration
	DeleteScanJob  bool
}
