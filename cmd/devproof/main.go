// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
