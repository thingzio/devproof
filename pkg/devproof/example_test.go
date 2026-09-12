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

package devproof_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thingzio/devproof"
	"github.com/thingzio/devproof/policy"
)

// sampleTree writes a small source directory and returns its path.
//
// Examples build from a temporary directory so that they run anywhere and
// leave nothing behind.
func sampleTree() string {
	dir, err := os.MkdirTemp("", "devproof-example")
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		panic(err)
	}
	files := map[string]string{
		"README.md":           "example\n",
		"config/service.yaml": "replicas: 3\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			panic(err)
		}
	}
	return dir
}

// Building a directory into a local OCI layout.
//
// The subject digest is a function of content alone, so the same tree always
// produces the same digest — on any machine, in any directory, at any time.
func ExampleClient_Build() {
	source := sampleTree()
	defer func() { _ = os.RemoveAll(source) }()

	layout, err := os.MkdirTemp("", "devproof-layout")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(layout) }()

	client, err := devproof.New()
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Build(context.Background(), devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + filepath.Join(layout, "artifact"),
		Tag:         "v1",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("subject:", result.SubjectDigest)
	fmt.Println("files:", result.FileCount)
	// Output:
	// subject: sha256:93847c4cd259d1ae9af9d61b3b84aaf82949007335883723f5770ac9cf90f437
	// files: 2
}

// Verifying a subject without a policy reports trust as not-evaluated, which
// is deliberately not the same as passing: a consumer whose trust
// configuration never took effect has no other way to notice.
func ExampleClient_Verify() {
	source := sampleTree()
	defer func() { _ = os.RemoveAll(source) }()

	layout, err := os.MkdirTemp("", "devproof-layout")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(layout) }()

	client, err := devproof.New()
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	destination := "oci-layout://" + filepath.Join(layout, "artifact")

	built, err := client.Build(ctx, devproof.BuildRequest{
		SourcePath:  source,
		Destination: destination,
	})
	if err != nil {
		panic(err)
	}

	report, err := client.Verify(ctx, devproof.VerifyRequest{Reference: built.Reference})
	if err != nil {
		panic(err)
	}

	fmt.Println("integrity:", report.Integrity)
	fmt.Println("trust:", report.Trust)
	// Output:
	// integrity: pass
	// trust: not-evaluated
}

// Expanding materializes a verified payload. The destination must not exist:
// v1 has no overwrite or merge option, so a failed expansion leaves nothing
// behind.
func ExampleClient_Expand() {
	source := sampleTree()
	defer func() { _ = os.RemoveAll(source) }()

	work, err := os.MkdirTemp("", "devproof-work")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(work) }()

	client, err := devproof.New()
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	built, err := client.Build(ctx, devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + filepath.Join(work, "artifact"),
	})
	if err != nil {
		panic(err)
	}

	expanded, err := client.Expand(ctx, devproof.ExpandRequest{
		Reference:   built.Reference,
		Destination: filepath.Join(work, "out"),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("files:", expanded.FileCount)
	fmt.Println("same subject:", expanded.SubjectDigest == built.SubjectDigest)
	// Output:
	// files: 2
	// same subject: true
}

// A policy makes verification say something. Without one, trust is
// not-evaluated; with one, an unsatisfied rule is a failure.
func ExampleClient_Verify_policy() {
	source := sampleTree()
	defer func() { _ = os.RemoveAll(source) }()

	layout, err := os.MkdirTemp("", "devproof-layout")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(layout) }()

	client, err := devproof.New()
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()

	built, err := client.Build(ctx, devproof.BuildRequest{
		SourcePath:  source,
		Destination: "oci-layout://" + filepath.Join(layout, "artifact"),
	})
	if err != nil {
		panic(err)
	}

	// This bundle was built without signing, so a policy demanding
	// provenance cannot be satisfied.
	report, err := client.Verify(ctx, devproof.VerifyRequest{
		Reference: built.Reference,
		Policy: &policy.Document{
			APIVersion: "devproof.thingz.io/v1alpha1",
			Kind:       "VerificationPolicy",
			Metadata:   policy.Metadata{Name: "requires-provenance"},
			Spec: policy.Spec{
				Provenance: policy.ProvenanceRules{Required: true},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("integrity:", report.Integrity)
	fmt.Println("trust:", report.Trust)
	fmt.Println("satisfied:", report.OK())
	// Output:
	// integrity: pass
	// trust: fail
	// satisfied: false
}

// Identity is a function of content, so building the same tree twice produces
// the same subject — which is what makes a bundle comparable across machines
// and rebuilds.
func ExampleClient_Build_reproducible() {
	source := sampleTree()
	defer func() { _ = os.RemoveAll(source) }()

	work, err := os.MkdirTemp("", "devproof-work")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(work) }()

	client, err := devproof.New()
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	digests := make([]string, 0, 2)
	for i, name := range []string{"first", "second"} {
		built, err := client.Build(ctx, devproof.BuildRequest{
			SourcePath:  source,
			Destination: "oci-layout://" + filepath.Join(work, name),
		})
		if err != nil {
			panic(fmt.Sprintf("build %d: %v", i, err))
		}
		digests = append(digests, built.SubjectDigest)
	}

	fmt.Println("identical:", digests[0] == digests[1])
	// Output:
	// identical: true
}
