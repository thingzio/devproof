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

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/thingzio/devproof/internal/repo"
)

// builtIn are the flags the library supplies, which the reference does not
// document because every command has them.
var builtIn = map[string]bool{"help": true, "version": true}

// treeFlags collects every flag the command tree accepts, and every command
// name.
func treeFlags(t *testing.T) (flags, commands map[string]bool) {
	t.Helper()

	app := &App{}
	root := app.command()

	flags = map[string]bool{}
	commands = map[string]bool{}

	for _, flag := range root.Flags {
		for _, name := range flag.Names() {
			flags[name] = true
		}
	}
	for _, command := range root.Commands {
		commands[command.Name] = true
		for _, flag := range command.Flags {
			for _, name := range flag.Names() {
				flags[name] = true
			}
		}
	}
	return flags, commands
}

// documentedFlags reads the flags and commands the CLI reference names.
func documentedFlags(t *testing.T) (flags, commands map[string]bool) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repo.Root(), "docs", "cli.md"))
	if err != nil {
		t.Fatalf("reading the CLI reference: %v", err)
	}
	text := string(data)

	flags = map[string]bool{}
	for _, match := range regexp.MustCompile(`--[a-z][a-z0-9-]*`).FindAllString(text, -1) {
		flags[match[2:]] = true
	}

	commands = map[string]bool{}
	for _, match := range regexp.MustCompile("(?m)^## `devproof ([a-z]+)`").FindAllStringSubmatch(text, -1) {
		commands[match[1]] = true
	}
	return flags, commands
}

// TestEveryFlagIsDocumented catches a flag that shipped without a reference
// entry.
//
// An undocumented flag is one nobody outside this repository can discover
// except by reading help output they have no reason to suspect is incomplete.
// It is also the shape a half-finished feature takes: the flag exists, the
// reference does not mention it, and nobody notices it never worked.
func TestEveryFlagIsDocumented(t *testing.T) {
	t.Parallel()

	flags, commands := treeFlags(t)
	documented, documentedCommands := documentedFlags(t)

	for name := range flags {
		// Single-letter aliases are spelled in help rather than in the
		// reference's option lists.
		if len(name) == 1 || builtIn[name] {
			continue
		}
		if !documented[name] {
			t.Errorf("--%s is accepted by the CLI and not documented in docs/cli.md", name)
		}
	}
	for name := range commands {
		if !documentedCommands[name] {
			t.Errorf("the %s command has no section in docs/cli.md", name)
		}
	}
}

// TestEveryDocumentedFlagExists catches the other direction.
//
// A reference naming a flag the binary does not accept is worse than silence:
// somebody writes it into a pipeline, the command exits with a usage error,
// and the documentation is what they stop trusting.
func TestEveryDocumentedFlagExists(t *testing.T) {
	t.Parallel()

	flags, commands := treeFlags(t)
	documented, documentedCommands := documentedFlags(t)

	for name := range documented {
		if builtIn[name] {
			continue
		}
		if !flags[name] {
			t.Errorf("docs/cli.md documents --%s, which no command accepts", name)
		}
	}
	for name := range documentedCommands {
		if !commands[name] {
			t.Errorf("docs/cli.md documents the %s command, which does not exist", name)
		}
	}
}
