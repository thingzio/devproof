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
	_ "embed"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/thingzio/devproof/pkg/fault"
)

const templateOp = "bundle.template"

// DefaultSpecName is the conventional file name for a bundle manifest.
const DefaultSpecName = "devproof.yaml"

//go:embed template.yaml
var specTemplate string

// sourcePathPlaceholder is the single substitution point in the template.
const sourcePathPlaceholder = "__SOURCE_PATH__"

// Template renders a starter manifest whose local source reads sourcePath.
//
// The result is a commented document rather than a marshaled struct, because
// its purpose is to answer "what can go here?" without sending anyone to the
// schema. Comments are the only part of a manifest that can do that, and they
// do not survive a round trip through the typed model.
//
// Only the source path varies. Generating the rest from an inspection of the
// directory was considered and rejected: a scan produces a valid manifest that
// teaches nothing, because it cannot show a git source, a filter, or a mount
// path that is not already there.
func Template(sourcePath string) ([]byte, error) {
	if sourcePath == "" {
		sourcePath = "."
	}

	// Encoded as a YAML scalar rather than interpolated raw, so a path
	// containing a colon, a leading dash, or anything else YAML treats as
	// syntax is quoted instead of changing the document's shape.
	encoded, err := yaml.Marshal(sourcePath)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, templateOp,
			"encoding the source path", err)
	}
	scalar := strings.TrimRight(string(encoded), "\n")

	// A path containing a newline -- legal on POSIX, however unlikely --
	// encodes as a multi-line block scalar, which cannot be substituted into
	// the middle of a line without destroying the surrounding indentation.
	// Double quoting escapes the newline and keeps the value on one line.
	if strings.Contains(scalar, "\n") {
		requoted, err := yaml.Marshal(&yaml.Node{
			Kind:  yaml.ScalarNode,
			Style: yaml.DoubleQuotedStyle,
			Value: sourcePath,
		})
		if err != nil {
			return nil, fault.Wrap(fault.CodeInvalidInput, templateOp,
				"encoding the source path", err)
		}
		scalar = strings.TrimRight(string(requoted), "\n")
	}

	rendered := strings.Replace(specTemplate, sourcePathPlaceholder, scalar, 1)

	// The template is data, and data can be edited into something that does
	// not parse. Reading it back means this function cannot hand out a
	// manifest that the loader would reject -- a scaffold that needs fixing
	// before it works is worse than no scaffold.
	if _, err := ParseSpec([]byte(rendered)); err != nil {
		return nil, fault.Wrap(fault.CodeInternal, templateOp,
			"the rendered manifest template is not a valid manifest", err)
	}
	return []byte(rendered), nil
}
