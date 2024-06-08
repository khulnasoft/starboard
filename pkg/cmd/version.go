package cmd

import (
	"fmt"
	"io"

	"github.com/khulnasoft/starboard/pkg/starboard"
	"github.com/spf13/cobra"
)

func NewVersionCmd(buildInfo starboard.BuildInfo, outWriter io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _ = fmt.Fprintf(outWriter, "Starboard Version: %+v\n", struct {
				Version string
				Commit  string
				Date    string
			}{Version: buildInfo.Version, Commit: buildInfo.Commit, Date: buildInfo.Date})
			return nil
		},
	}
	return cmd
}
