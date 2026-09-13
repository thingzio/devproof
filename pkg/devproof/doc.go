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

// Package devproof is a Go-embeddable, extensible, multi-source artifact
// bundler with canonical identity across platforms, provenance evidence,
// policy-based verification, and safe deterministic expansion.
//
// It resolves content from one or more sources, composes it into a canonical
// filesystem tree, packages that tree as an OCI artifact, records provenance
// as independently verifiable evidence, evaluates the result against policy,
// and safely expands the artifact back to a filesystem.
//
// # Identity
//
// A bundle's OCI subject digest is a function of the canonical payload and the
// bundle format version, and of nothing else. Source URLs, timestamps, builder
// identity, registry location, tags, signatures, and attestations do not
// affect it. Two equal canonical trees therefore have equal subject digests
// even when assembled from different sources by different builders, and
// evidence can be added, renewed, or copied without changing what it
// describes.
//
// # Three independent answers
//
// Verification reports integrity, trust, and semantics separately. Integrity
// asks whether the descriptors, config inventory, layer, and tree agree. Trust
// asks whether the supplied evidence satisfies the caller's policy. Semantics
// asks whether a caller-supplied validator accepts the payload. Passing
// integrity never implies trust, and the absence of a policy reports
// "not-evaluated", never "pass".
//
// DevProof proves artifact identity, integrity, provenance, and policy
// compliance under a supplied trust policy. It does not claim that payload
// content is correct, safe, vulnerability-free, or semantically valid.
//
// # Layout
//
// This package is the facade. The operation contracts live alongside it:
//
//   - [github.com/thingzio/devproof/pkg/bundle]: format constants, manifest, lock,
//     inventory, and resource limits.
//   - [github.com/thingzio/devproof/pkg/source]: the source resolver contract and
//     the built-in local-path and HTTPS Git resolvers.
//   - [github.com/thingzio/devproof/pkg/artifact]: OCI descriptors, references,
//     and the transport contract.
//   - [github.com/thingzio/devproof/pkg/evidence]: provenance statements and the
//     attester contract.
//   - [github.com/thingzio/devproof/pkg/policy]: verification policy documents and
//     result types.
//
// Canonical byte production is deliberately internal. It is reached through
// stable high-level operations rather than low-level knobs, because every one
// of those bytes is a compatibility surface.
package devproof
