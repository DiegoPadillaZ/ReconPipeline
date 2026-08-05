package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=x.y.z".
var version = "1.0.0-dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print ThreatLens version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("ThreatLens %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
