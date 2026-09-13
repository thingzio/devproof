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
	"fmt"

	"github.com/thingzio/devproof/pkg/fault"
)

// Bound identifies one configurable resource limit.
//
// Limits are enumerated rather than addressed by field name so that a
// verification report can say which input supplied each effective value
// without stringly-typed keys (DP-021).
type Bound int

// The configurable bounds. Values are not serialized; Bound.String is.
const (
	BoundMaxFiles Bound = iota
	BoundMaxFileBytes
	BoundMaxExpandedBytes
	BoundMaxCompressedBytes
	BoundMaxCompressionRatio
	BoundMaxPathBytes
	BoundMaxPathSegmentBytes
	BoundMaxPathDepth
	BoundMaxConfigBytes
	BoundMaxManifestBytes
	BoundMaxSpecBytes
	BoundMaxLockBytes
	BoundMaxReferrers
	BoundMaxEvidenceBytes
	BoundMaxParallelSources
)

// Origin records which input supplied a limit's effective value.
type Origin string

// Limit origins, from weakest to strongest precedence. Precedence is not
// "last wins": every input may only tighten, so the effective value is the
// minimum across all of them (DP-021).
const (
	OriginDefault Origin = "default"
	OriginClient  Origin = "client"
	OriginRequest Origin = "request"
	OriginPolicy  Origin = "policy"
)

// Limits bounds the resources one operation may consume.
//
// A zero field means "unset" and inherits the default. Zero never means
// unlimited: an unbounded extraction is the decompression-bomb case, and
// spelling it as the zero value would make it the accidental default.
// Every field carries explicit json and yaml tags. Without them yaml.v3
// derives a key by lowercasing the whole field name, so a policy would have
// had to spell MaxFiles as "maxfiles" -- a spelling no document used and none
// should. The tags are the serialized names, and a policy is canonicalized by
// them, so they are a compatibility surface rather than a formatting choice.
type Limits struct {
	// MaxFiles bounds the number of files in a bundle.
	MaxFiles int64 `json:"maxFiles,omitempty" yaml:"maxFiles,omitempty"`
	// MaxFileBytes bounds any single file's size.
	MaxFileBytes int64 `json:"maxFileBytes,omitempty" yaml:"maxFileBytes,omitempty"`
	// MaxExpandedBytes bounds the total uncompressed payload.
	MaxExpandedBytes int64 `json:"maxExpandedBytes,omitempty" yaml:"maxExpandedBytes,omitempty"`
	// MaxCompressedBytes bounds the compressed layer.
	MaxCompressedBytes int64 `json:"maxCompressedBytes,omitempty" yaml:"maxCompressedBytes,omitempty"`
	// MaxCompressionRatio bounds expanded bytes divided by compressed bytes.
	MaxCompressionRatio int64 `json:"maxCompressionRatio,omitempty" yaml:"maxCompressionRatio,omitempty"`
	// MaxPathBytes bounds a canonical path's UTF-8 length.
	MaxPathBytes int64 `json:"maxPathBytes,omitempty" yaml:"maxPathBytes,omitempty"`
	// MaxPathSegmentBytes bounds one path segment's UTF-8 length.
	MaxPathSegmentBytes int64 `json:"maxPathSegmentBytes,omitempty" yaml:"maxPathSegmentBytes,omitempty"`
	// MaxPathDepth bounds a canonical path's segment count.
	MaxPathDepth int64 `json:"maxPathDepth,omitempty" yaml:"maxPathDepth,omitempty"`
	// MaxConfigBytes bounds the DevProof config blob.
	MaxConfigBytes int64 `json:"maxConfigBytes,omitempty" yaml:"maxConfigBytes,omitempty"`
	// MaxManifestBytes bounds the OCI manifest.
	MaxManifestBytes int64 `json:"maxManifestBytes,omitempty" yaml:"maxManifestBytes,omitempty"`
	// MaxSpecBytes bounds a manifest document.
	MaxSpecBytes int64 `json:"maxSpecBytes,omitempty" yaml:"maxSpecBytes,omitempty"`
	// MaxLockBytes bounds a lock document.
	MaxLockBytes int64 `json:"maxLockBytes,omitempty" yaml:"maxLockBytes,omitempty"`
	// MaxReferrers bounds how many referrer descriptors are enumerated.
	MaxReferrers int64 `json:"maxReferrers,omitempty" yaml:"maxReferrers,omitempty"`
	// MaxEvidenceBytes bounds one evidence object.
	MaxEvidenceBytes int64 `json:"maxEvidenceBytes,omitempty" yaml:"maxEvidenceBytes,omitempty"`
	// MaxParallelSources bounds concurrent source resolution.
	MaxParallelSources int64 `json:"maxParallelSources,omitempty" yaml:"maxParallelSources,omitempty"`
}

// MaxRepresentableFileBytes is the largest file format v1 can encode: eleven
// octal digits in the USTAR size field, one byte short of 8 GiB.
//
// This is a property of the format, not a policy choice, so it is the ceiling
// for maxFileBytes rather than a separate check. Format v1 describes an
// oversized file with no PAX size record; see DP-019.
const MaxRepresentableFileBytes = int64(1)<<33 - 1

// Units for limit diagnostics. A message that says "exceeds the maximum of
// 1000" is not actionable; one that says "1000 to one" names what was
// measured.
const (
	unitBytes     = "bytes"
	unitFiles     = "files"
	unitRatio     = "to one"
	unitSegments  = "segments"
	unitReferrers = "referrers"
	unitSources   = "sources"
)

// boundField binds each Bound to its field and its documented default and
// ceiling (DP-020). A table keeps Defaults, Validate, and Intersect as loops
// instead of fifteen repeated lines each, and makes adding a bound a
// single-line change that all three pick up.
var boundFields = []struct {
	bound    Bound
	name     string
	get      func(*Limits) *int64
	def      int64
	ceiling  int64
	unitHint string
}{
	{BoundMaxFiles, "maxFiles", func(l *Limits) *int64 { return &l.MaxFiles }, 100_000, 1_000_000, unitFiles},
	{BoundMaxFileBytes, "maxFileBytes", func(l *Limits) *int64 { return &l.MaxFileBytes }, 1 << 30, MaxRepresentableFileBytes, unitBytes},
	{BoundMaxExpandedBytes, "maxExpandedBytes", func(l *Limits) *int64 { return &l.MaxExpandedBytes }, 8 << 30, 64 << 30, unitBytes},
	{BoundMaxCompressedBytes, "maxCompressedBytes", func(l *Limits) *int64 { return &l.MaxCompressedBytes }, 2 << 30, 16 << 30, unitBytes},
	{BoundMaxCompressionRatio, "maxCompressionRatio", func(l *Limits) *int64 { return &l.MaxCompressionRatio }, 200, 1000, unitRatio},
	{BoundMaxPathBytes, "maxPathBytes", func(l *Limits) *int64 { return &l.MaxPathBytes }, 1024, 4096, unitBytes},
	{BoundMaxPathSegmentBytes, "maxPathSegmentBytes", func(l *Limits) *int64 { return &l.MaxPathSegmentBytes }, 255, 255, unitBytes},
	{BoundMaxPathDepth, "maxPathDepth", func(l *Limits) *int64 { return &l.MaxPathDepth }, 64, 256, unitSegments},
	{BoundMaxConfigBytes, "maxConfigBytes", func(l *Limits) *int64 { return &l.MaxConfigBytes }, 64 << 20, 256 << 20, unitBytes},
	{BoundMaxManifestBytes, "maxManifestBytes", func(l *Limits) *int64 { return &l.MaxManifestBytes }, 4 << 20, 4 << 20, unitBytes},
	{BoundMaxSpecBytes, "maxSpecBytes", func(l *Limits) *int64 { return &l.MaxSpecBytes }, 1 << 20, 16 << 20, unitBytes},
	{BoundMaxLockBytes, "maxLockBytes", func(l *Limits) *int64 { return &l.MaxLockBytes }, 16 << 20, 64 << 20, unitBytes},
	{BoundMaxReferrers, "maxReferrers", func(l *Limits) *int64 { return &l.MaxReferrers }, 256, 4096, unitReferrers},
	{BoundMaxEvidenceBytes, "maxEvidenceBytes", func(l *Limits) *int64 { return &l.MaxEvidenceBytes }, 16 << 20, 64 << 20, unitBytes},
	{BoundMaxParallelSources, "maxParallelSources", func(l *Limits) *int64 { return &l.MaxParallelSources }, 4, 64, unitSources},
}

func (b Bound) String() string {
	for _, f := range boundFields {
		if f.bound == b {
			return f.name
		}
	}
	return "unknown"
}

// DefaultLimits returns the documented defaults (DP-020).
func DefaultLimits() Limits {
	var l Limits
	for _, f := range boundFields {
		*f.get(&l) = f.def
	}
	return l
}

// Ceilings returns the documented hard maximums. A caller may not configure
// past these, because beyond them the format's own portability claims stop
// holding: a path segment over 255 bytes, for instance, cannot be written on
// most filesystems, so such a bundle could be built but never expanded.
func Ceilings() Limits {
	var l Limits
	for _, f := range boundFields {
		*f.get(&l) = f.ceiling
	}
	return l
}

// WithDefaults returns a copy with every unset bound filled in.
func (l Limits) WithDefaults() Limits {
	out := l
	for _, f := range boundFields {
		p := f.get(&out)
		if *p == 0 {
			*p = f.def
		}
	}
	return out
}

// Validate rejects negative and above-ceiling values.
//
// It does not fill defaults: a caller that supplied an impossible bound
// should hear about it, not have it quietly replaced.
func (l Limits) Validate() error {
	for _, f := range boundFields {
		v := *f.get(&l)
		switch {
		case v < 0:
			return fault.New(fault.CodeInvalidInput, "limits",
				fmt.Sprintf("%s must not be negative, got %d", f.name, v))
		case v > f.ceiling:
			return fault.New(fault.CodeInvalidInput, "limits",
				fmt.Sprintf("%s exceeds the maximum of %d %s, got %d",
					f.name, f.ceiling, f.unitHint, v))
		}
	}
	return nil
}

// Resolved is an effective limit set plus the origin of each value.
type Resolved struct {
	Limits Limits
	origin map[Bound]Origin
}

// Origin reports which input supplied b's effective value.
func (r Resolved) Origin(b Bound) Origin {
	if o, ok := r.origin[b]; ok {
		return o
	}
	return OriginDefault
}

// Input is one contributor to the effective limits.
type Input struct {
	Origin Origin
	Limits Limits
}

// Resolve intersects every supplied input over the defaults: for each bound,
// the effective value is the smallest one anybody asked for, and the origin
// records who asked (DP-021).
//
// Intersection rather than override is what stops a verification policy from
// being usable as privilege escalation: a policy shipped with an artifact can
// tighten what the embedding application allowed, never widen it.
func Resolve(inputs ...Input) Resolved {
	out := Resolved{
		Limits: DefaultLimits(),
		origin: make(map[Bound]Origin, len(boundFields)),
	}
	for _, f := range boundFields {
		out.origin[f.bound] = OriginDefault
	}

	for _, in := range inputs {
		for _, f := range boundFields {
			candidate := *f.get(&in.Limits)
			if candidate <= 0 {
				continue
			}
			current := f.get(&out.Limits)
			if candidate < *current {
				*current = candidate
				out.origin[f.bound] = in.Origin
			}
		}
	}
	return out
}
