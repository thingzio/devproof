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
	stderrors "errors"
	"strings"
	"testing"

	"github.com/thingzio/devproof/internal/fault"
)

func digestOf(s string) string { return DigestOf([]byte(s)).String() }

func validConfig() *Config {
	return &Config{
		SchemaVersion: ConfigSchemaVersion,
		Format:        FormatV1,
		TreeDigest:    digestOf("tree"),
		FileCount:     2,
		TotalSize:     8,
		Files: []ConfigFile{
			{Path: "a.txt", Mode: ModeFile, Size: 5, Digest: digestOf("hello")},
			{Path: "b/c.sh", Mode: ModeExecutable, Size: 3, Digest: digestOf("abc")},
		},
	}
}

func TestConfigValidateAcceptsWellFormed(t *testing.T) {
	t.Parallel()

	if err := validConfig().Validate(); err != nil {
		t.Errorf("a well-formed config was rejected: %v", err)
	}
}

// An empty inventory is structurally valid even though composition refuses to
// build one. The reader must not have an undefined case.
func TestConfigValidateAcceptsEmptyInventory(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		SchemaVersion: ConfigSchemaVersion,
		Format:        FormatV1,
		TreeDigest:    digestOf("empty tree"),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("an empty inventory was rejected: %v", err)
	}
}

// A config that is internally inconsistent can be satisfied by more than one
// archive, which is exactly what it exists to prevent.
func TestConfigValidateRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
		code   fault.Code
	}{
		{
			"unknown schema version",
			func(c *Config) { c.SchemaVersion = 2 },
			fault.CodeUnsupportedVersion,
		},
		{
			"unknown format",
			func(c *Config) { c.Format = "devproof-bundle-v2" },
			fault.CodeUnsupportedVersion,
		},
		{
			"invalid tree digest",
			func(c *Config) { c.TreeDigest = "sha256:zzz" },
			fault.CodeInvalidArtifact,
		},
		{
			"file count disagrees with the list",
			func(c *Config) { c.FileCount = 3 },
			fault.CodeInvalidArtifact,
		},
		{
			"total size disagrees with the entries",
			func(c *Config) { c.TotalSize = 99 },
			fault.CodeInvalidArtifact,
		},
		{
			"empty path",
			func(c *Config) { c.Files[0].Path = "" },
			fault.CodeInvalidArtifact,
		},
		{
			"unnormalized mode",
			func(c *Config) { c.Files[0].Mode = 0o600 },
			fault.CodeInvalidArtifact,
		},
		{
			"negative size",
			func(c *Config) { c.Files[0].Size = -1; c.TotalSize = 2 },
			fault.CodeInvalidArtifact,
		},
		{
			"invalid entry digest",
			func(c *Config) { c.Files[0].Digest = "notadigest" },
			fault.CodeInvalidArtifact,
		},
		{
			"unsorted entries",
			func(c *Config) { c.Files[0], c.Files[1] = c.Files[1], c.Files[0] },
			fault.CodeInvalidArtifact,
		},
		{
			"duplicate path",
			func(c *Config) { c.Files[1] = c.Files[0]; c.TotalSize = 10 },
			fault.CodeInvalidArtifact,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			tc.mutate(cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("an invalid config validated")
			}
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), tc.code)
			}
		})
	}
}

// A field this build does not understand may be load-bearing for whoever
// produced the bundle. Ignoring it would mean verifying something other than
// what was published.
func TestParseConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	raw := `{"schemaVersion":1,"format":"devproof-bundle-v1","treeDigest":"` +
		digestOf("t") + `","fileCount":0,"totalSize":0,"files":[],"signature":"trust me"}`

	if _, err := ParseConfig([]byte(raw)); !stderrors.Is(err, fault.CodeInvalidArtifact) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidArtifact)
	}
}

func TestParseConfigRejectsTrailingData(t *testing.T) {
	t.Parallel()

	raw := `{"schemaVersion":1,"format":"devproof-bundle-v1","treeDigest":"` +
		digestOf("t") + `","fileCount":0,"totalSize":0,"files":[]} {"more":1}`

	if _, err := ParseConfig([]byte(raw)); !stderrors.Is(err, fault.CodeInvalidArtifact) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInvalidArtifact)
	}
}

func TestParseConfigRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "{", "null", "[]", "not json"} {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("ParseConfig(%q) accepted malformed input", raw)
		}
	}
}

func TestParseConfigRoundTrip(t *testing.T) {
	t.Parallel()

	raw := `{"fileCount":1,"files":[{"digest":"` + digestOf("hello") +
		`","mode":420,"path":"a.txt","size":5}],"format":"devproof-bundle-v1",` +
		`"schemaVersion":1,"totalSize":5,"treeDigest":"` + digestOf("tree") + `"}`

	cfg, err := ParseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.FileCount != 1 || len(cfg.Files) != 1 {
		t.Fatalf("parsed %d files", len(cfg.Files))
	}
	if cfg.Files[0].Path != "a.txt" || cfg.Files[0].Mode != ModeFile || cfg.Files[0].Size != 5 {
		t.Errorf("entry = %+v", cfg.Files[0])
	}
}

func TestDigestRoundTrip(t *testing.T) {
	t.Parallel()

	d := DigestOf([]byte("content"))

	parsed, err := ParseDigest(d.String())
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if parsed != d {
		t.Error("round trip changed the digest")
	}
	if d.IsZero() {
		t.Error("a real digest reported IsZero")
	}
	if !(Digest{}).IsZero() {
		t.Error("the zero digest did not report IsZero")
	}
	if !strings.HasPrefix(d.String(), "sha256:") {
		t.Errorf("String() = %q, want an algorithm prefix", d.String())
	}
	if len(d.Hex()) != 64 {
		t.Errorf("Hex() is %d characters, want 64", len(d.Hex()))
	}
}
