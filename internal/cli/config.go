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
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/thingzio/devproof/internal/fault"
)

// Configuration precedence, highest first:
//
//  1. an explicit command-line flag;
//  2. a DEVPROOF_-prefixed environment variable;
//  3. the configuration file; and
//  4. the built-in default.
//
// The order is the usual one, and the reason it is worth stating is that the
// alternatives are all worse: a file that overrode a flag would make a one-off
// override impossible, and an environment variable that overrode a flag would
// make a CI runner's ambient settings silently win over what a script asked
// for.
//
// Only settings that are safe to persist live in the file. Anything naming a
// specific artifact — a reference, a destination, a tag — is deliberately
// absent: those belong to an invocation, and a file that could change which
// artifact a command acted on would make the same command line mean different
// things on different machines.

// configFileName is the file looked for when --config is not given.
const configFileName = "devproof.yaml"

// Config is the persisted configuration.
//
// Decoding is strict. A misspelled key in a configuration file is a setting
// that silently does not apply, and the failure shows up later as behavior
// nobody can explain.
type Config struct {
	// Format is the default output rendering.
	Format string `yaml:"format,omitempty"`
	// Verbose and Debug set default diagnostic levels.
	Verbose bool `yaml:"verbose,omitempty"`
	Debug   bool `yaml:"debug,omitempty"`
	// NoColor disables color regardless of terminal detection.
	NoColor bool `yaml:"noColor,omitempty"`
	// Timeout is the default overall operation deadline, as a duration
	// string.
	Timeout string `yaml:"timeout,omitempty"`
	// Policy is a verification policy applied when --policy is not given.
	//
	// A default policy can only make verification stricter: without one,
	// trust reports not-evaluated. There is no setting that can relax
	// verification, because a file that could turn integrity checking off
	// would be the most valuable file on the machine to an attacker.
	Policy string `yaml:"policy,omitempty"`
	// TrustRoot is a default Sigstore trusted root.
	TrustRoot string `yaml:"trustRoot,omitempty"`
	// FulcioURL and RekorURL select non-default Sigstore instances, which is
	// what a private deployment needs.
	FulcioURL string `yaml:"fulcioUrl,omitempty"`
	RekorURL  string `yaml:"rekorUrl,omitempty"`
}

// loadConfig reads the configuration file.
//
// An explicit path that does not exist is an error, because the operator said
// to use it. A default path that does not exist is not: most invocations have
// no configuration file at all.
func loadConfig(path string, explicit bool) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // an operator-supplied path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return &Config{}, nil
		}
		return nil, fault.Wrap(fault.CodeInvalidInput, "cli",
			"reading the configuration file", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, "cli",
			"decoding "+path, err)
	}
	if config.Format != "" {
		if format := Format(config.Format); format != FormatText && format != FormatJSON {
			return nil, fault.New(fault.CodeInvalidInput, "cli",
				"configuration sets an unknown format "+config.Format+"; use text or json")
		}
	}
	return &config, nil
}

// defaultConfigPath returns the file consulted when --config is absent.
//
// The per-user configuration directory, and only there. A file picked up from
// the working directory would mean that cloning a repository and running a
// command inside it could change what that command does, which makes a
// configuration file part of an artifact's attack surface.
func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "devproof", configFileName)
}
