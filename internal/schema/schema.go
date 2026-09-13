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

// Package schema names the published JSON Schemas and locates them on disk.
//
// The schemas in the repository's schemas/ directory are normative: they
// describe the documents DevProof reads, and the Go decoders in pkg/bundle
// and pkg/policy are one implementation of them, in the same way that
// pkg/conformance is one implementation of the bundle format specification.
//
// This package exists so the drift test has one place to name them. It
// deliberately does not embed them into the binary: nothing at runtime
// validates a document against a schema, because the decoders already reject
// everything the schema forbids, and shipping a second enforcement path would
// mean two things to keep in step rather than one.
package schema

import (
	"path/filepath"

	"github.com/thingzio/devproof/internal/repo"
)

// Schema file names, relative to the schemas/ directory.
const (
	Bundle             = "bundle.v1alpha1.schema.json"
	BundleLock         = "bundle-lock.v1alpha1.schema.json"
	BundleConfig       = "bundle-config.v1.schema.json"
	VerificationPolicy = "verification-policy.v1alpha1.schema.json"
)

// All lists every published schema.
func All() []string {
	return []string{Bundle, BundleLock, BundleConfig, VerificationPolicy}
}

// Path returns the path of one schema file.
func Path(name string) string {
	return filepath.Join(repo.Root(), "schemas", name)
}
