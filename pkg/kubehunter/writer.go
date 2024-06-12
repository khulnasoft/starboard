package kubehunter

import (
	"context"

	starboard "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
)

type Writer interface {
	Write(ctx context.Context, report starboard.KubeHunterOutput, cluster string) error
}
