// Command devproof builds, verifies, and expands immutable bundles.
//
// It is a thin adapter over the Go SDK: every command maps to one public SDK
// operation, so anything the CLI can do is reachable from an embedding
// application without shelling out (DP-001).
package main

import (
	"context"
	"os"

	"github.com/thingzio/devproof/internal/cli"
)

func main() {
	// The exit code comes back rather than being set from inside, so the
	// whole command tree can be run in-process by a test and its exit status
	// asserted — which is the only way to know the documented mapping holds.
	os.Exit(cli.Run(context.Background(), os.Args, cli.DefaultStreams()))
}
