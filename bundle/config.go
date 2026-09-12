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

package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/thingzio/devproof/internal/fault"
)

const configOp = "bundle.config"

// ConfigSchemaVersion is the schema version of the v1 config blob.
const ConfigSchemaVersion = 1

// Config is the DevProof config blob: the exact inventory of what a bundle
// contains.
//
// It exists so that verification never has to trust tar extraction behavior.
// A consumer can check every entry against this list before writing anything,
// which is what makes "the archive contains exactly this and nothing else" a
// checkable claim rather than an assumption about the extractor.
//
// The struct deliberately has nowhere to put a bundle name, a source, a
// timestamp, a builder, a registry reference, a tag, an annotation, or a
// signature. Those belong to evidence, and admitting any of them here would
// make two builds of identical content produce different subject digests
// (DP-002).
type Config struct {
	SchemaVersion int          `json:"schemaVersion"`
	Format        Format       `json:"format"`
	TreeDigest    string       `json:"treeDigest"`
	FileCount     int64        `json:"fileCount"`
	TotalSize     int64        `json:"totalSize"`
	Files         []ConfigFile `json:"files"`
}

// ConfigFile is one inventory entry.
type ConfigFile struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

// ParseConfig decodes and validates a config blob.
//
// Decoding is strict: an unknown field is an error, not something to ignore.
// A field this build does not understand may be load-bearing for the producer,
// and silently dropping it would mean verifying something other than what was
// published.
func ParseConfig(data []byte) (*Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, configOp, "decoding config blob", err)
	}
	if decoder.More() {
		return nil, fault.New(fault.CodeInvalidArtifact, configOp,
			"config blob contains trailing data after the JSON object")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks every internal consistency rule the format defines.
//
// The checks are exhaustive rather than representative because this is the
// document a verifier compares the layer against: a config that is internally
// inconsistent can be made to agree with more than one archive.
func (c *Config) Validate() error {
	reject := func(msg string) error {
		return fault.New(fault.CodeInvalidArtifact, configOp, msg)
	}

	if c.SchemaVersion != ConfigSchemaVersion {
		return fault.New(fault.CodeUnsupportedVersion, configOp,
			fmt.Sprintf("config schema version %d is not supported; this build reads %d",
				c.SchemaVersion, ConfigSchemaVersion))
	}
	if !Supported(c.Format) {
		return fault.New(fault.CodeUnsupportedVersion, configOp,
			fmt.Sprintf("bundle format %q is not supported", c.Format))
	}
	if _, err := ParseDigest(c.TreeDigest); err != nil {
		return fault.Wrap(fault.CodeInvalidArtifact, configOp, "config tree digest is invalid", err)
	}

	if c.FileCount != int64(len(c.Files)) {
		return reject(fmt.Sprintf("config declares %d files but lists %d",
			c.FileCount, len(c.Files)))
	}

	var total int64
	var previous string
	for i := range c.Files {
		file := &c.Files[i]

		switch {
		case file.Path == "":
			return reject(fmt.Sprintf("config entry %d has an empty path", i))
		case file.Mode != ModeFile && file.Mode != ModeExecutable:
			return fault.New(fault.CodeInvalidArtifact, configOp,
				fmt.Sprintf("config entry mode %#o is not normalized to %#o or %#o",
					file.Mode, ModeFile, ModeExecutable)).WithPath(file.Path)
		case file.Size < 0:
			return fault.New(fault.CodeInvalidArtifact, configOp,
				"config entry has a negative size").WithPath(file.Path)
		}

		if _, err := ParseDigest(file.Digest); err != nil {
			return fault.Wrap(fault.CodeInvalidArtifact, configOp,
				"config entry digest is invalid", err).WithPath(file.Path)
		}

		// Strictly increasing catches an unsorted inventory and a duplicate
		// path in one comparison. Either would let two different archives
		// satisfy the same config.
		if i > 0 && file.Path <= previous {
			if file.Path == previous {
				return fault.New(fault.CodeInvalidArtifact, configOp,
					"config lists a duplicate path").WithPath(file.Path)
			}
			return fault.New(fault.CodeInvalidArtifact, configOp,
				fmt.Sprintf("config is not sorted by path: %q follows %q", file.Path, previous)).
				WithPath(file.Path)
		}
		previous = file.Path

		// Checked before adding, so a hostile config cannot overflow its way
		// to a small declared total.
		if total > int64(^uint64(0)>>1)-file.Size {
			return reject("config total size overflows")
		}
		total += file.Size
	}

	if c.TotalSize != total {
		return reject(fmt.Sprintf("config declares a total of %d bytes but its entries sum to %d",
			c.TotalSize, total))
	}
	return nil
}
