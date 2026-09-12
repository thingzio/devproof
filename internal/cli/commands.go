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
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devproof/pkg/devproof"
	"github.com/thingzio/devproof/pkg/policy"
)

// flagRequireDigest rejects a tag before anything is fetched. Shared by every
// command that reads a subject.
const flagRequireDigest = "require-digest"

func (a *App) lockCommand() *cli.Command {
	return &cli.Command{
		Name:  "lock",
		Usage: "resolve a manifest and write its immutable lock",
		Description: "Resolves every source a manifest declares and records what they\n" +
			"resolved to. Writing is all-or-nothing: a manifest whose sources partly\n" +
			"fail produces no lock at all.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "file", Aliases: []string{"f"},
				Usage: "manifest to resolve", Value: "devproof.yaml"},
			&cli.StringFlag{Name: "to", Usage: "where to write the lock"},
			&cli.BoolFlag{Name: "check",
				Usage: "verify an existing lock without writing"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, cancel := a.withTimeout(ctx)
			defer cancel()

			client, err := a.client(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			a.printer.Progress().Step("resolving sources")
			result, err := client.Lock(ctx, devproof.LockRequest{
				SpecPath:   cmd.String("file"),
				OutputPath: cmd.String("to"),
				Check:      cmd.Bool("check"),
			})
			if err != nil {
				return err
			}

			return a.printer.Result("LockResult", result, result.LockDigest, func(w io.Writer) {
				Field(w, "lock", result.OutputPath)
				Field(w, "lock digest", result.LockDigest)
				Field(w, "manifest digest", result.ManifestDigest)
				Field(w, "tree digest", result.TreeDigest)
				Field(w, "sources", fmt.Sprint(result.SourceCount))
				Field(w, "files", fmt.Sprint(result.FileCount))
			})
		},
	}
}

func (a *App) buildCommand() *cli.Command {
	return &cli.Command{
		Name:      "build",
		Usage:     "build and publish a bundle",
		ArgsUsage: "[SOURCE_DIRECTORY]",
		Description: "Builds from a manifest, or directly from a single directory given as\n" +
			"an argument. Blobs are published before the manifest, the stored manifest\n" +
			"is read back and compared, and any tag is assigned last.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "manifest to build"},
			&cli.StringFlag{Name: "to", Usage: "destination: oci:// or oci-layout://", Required: true},
			&cli.StringFlag{Name: "tag", Usage: "tag to assign, after publication succeeds"},
			&cli.StringFlag{Name: "lock", Usage: "lock to enforce"},
			&cli.BoolFlag{Name: "update-lock",
				Usage: "resolve afresh instead of enforcing the existing lock"},
			&cli.BoolFlag{Name: "no-lock", Usage: "build without a lock"},
			&cli.StringFlag{Name: "mount", Usage: "mount a direct source below a prefix"},
			&cli.StringSliceFlag{Name: "include", Usage: "selection pattern; repeatable"},
			&cli.StringSliceFlag{Name: "exclude", Usage: "rejection pattern; repeatable"},
			&cli.BoolFlag{Name: "sign", Usage: "sign provenance and attach it to the subject"},
			&cli.StringFlag{Name: "key",
				Usage: "sign with a PEM private key instead of keyless"},
			&cli.StringFlag{Name: "fulcio-url", Usage: "Fulcio instance for keyless signing"},
			&cli.StringFlag{Name: "rekor-url", Usage: "Rekor instance for keyless signing"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, cancel := a.withTimeout(ctx)
			defer cancel()

			var extra []devproof.Option
			if cmd.Bool("sign") {
				signing, signErr := a.signingOptions(cmd)
				if signErr != nil {
					return signErr
				}
				extra = append(extra, signing...)
			}

			client, err := a.client(cmd, extra...)
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			request := devproof.BuildRequest{
				SpecPath:    cmd.String("file"),
				SourcePath:  cmd.Args().First(),
				MountPath:   cmd.String("mount"),
				Include:     cmd.StringSlice("include"),
				Exclude:     cmd.StringSlice("exclude"),
				LockPath:    cmd.String("lock"),
				UpdateLock:  cmd.Bool("update-lock"),
				SkipLock:    cmd.Bool("no-lock"),
				Destination: cmd.String("to"),
				Tag:         cmd.String("tag"),
				Attest:      cmd.Bool("sign"),
			}

			a.printer.Progress().Step("building and publishing")
			result, err := client.Build(ctx, request)
			if err != nil {
				return err
			}

			// Quiet output is the canonical digest reference: the one value a
			// pipeline wants, and the one that cannot move under it.
			return a.printer.Result("BuildResult", result, result.Reference, func(w io.Writer) {
				Field(w, "reference", result.Reference)
				Field(w, "subject", result.SubjectDigest)
				Field(w, "tree digest", result.TreeDigest)
				Field(w, "format", result.Format)
				Field(w, "files", fmt.Sprint(result.FileCount))
				Field(w, "bytes", fmt.Sprint(result.TotalBytes))
				Field(w, "layer bytes", fmt.Sprint(result.LayerBytes))
				if result.Tag != "" {
					Field(w, "tag", result.Tag)
				}
				if result.Evidence != nil {
					Field(w, "evidence", result.Evidence.Digest)
					Field(w, "attester", result.Evidence.Attester)
					Field(w, "storage", result.Evidence.Storage)
				}
			})
		},
	}
}

func (a *App) verifyCommand() *cli.Command {
	return &cli.Command{
		Name:      "verify",
		Usage:     "verify integrity, evidence, and policy",
		ArgsUsage: "REFERENCE",
		Description: "Integrity is always checked and cannot be disabled. Trust is checked\n" +
			"only when a policy is supplied; without one it reports not-evaluated,\n" +
			"which is not the same as passing.",
		Flags: append(verificationFlags(),
			&cli.StringFlag{Name: "policy", Usage: "verification policy to apply"},
			&cli.BoolFlag{Name: flagRequireDigest,
				Usage: "reject a tag reference before fetching anything"},
		),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, cancel := a.withTimeout(ctx)
			defer cancel()

			reference := cmd.Args().First()
			if reference == "" {
				return usageError("verify needs a reference to verify")
			}

			extra, err := a.verificationOptions(cmd)
			if err != nil {
				return err
			}
			client, err := a.client(cmd, extra...)
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			a.printer.Progress().Step("verifying %s", reference)
			policyPath := a.setting(cmd, "policy", a.config.Policy)
			a.warnUnusedTrustMaterial(cmd, policyPath)

			report, err := client.Verify(ctx, devproof.VerifyRequest{
				Reference:     reference,
				RequireDigest: cmd.Bool(flagRequireDigest),
				PolicyPath:    policyPath,
			})
			if err != nil {
				return err
			}

			// A failed policy is a failed command. Printing a report that
			// says "fail" and exiting zero would make every CI gate built on
			// this useless.
			if !report.OK() {
				_ = a.printer.Result("VerifyResult", report, "", func(w io.Writer) {
					renderReport(w, report)
				})
				return policyFailure(report)
			}

			return a.printer.Result("VerifyResult", report, report.SubjectDigest, func(w io.Writer) {
				renderReport(w, report)
			})
		},
	}
}

func (a *App) expandCommand() *cli.Command {
	return &cli.Command{
		Name:      "expand",
		Usage:     "verify and materialize a bundle",
		ArgsUsage: "REFERENCE",
		Description: "The destination must not exist. There is no force, merge, or\n" +
			"ownership-preservation option: a failed expansion leaves nothing behind.",
		Flags: append(verificationFlags(),
			&cli.StringFlag{Name: "to", Usage: "destination directory", Required: true},
			&cli.StringFlag{Name: "policy", Usage: "verification policy to apply"},
			&cli.BoolFlag{Name: flagRequireDigest,
				Usage: "reject a tag reference before fetching anything"},
		),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, cancel := a.withTimeout(ctx)
			defer cancel()

			reference := cmd.Args().First()
			if reference == "" {
				return usageError("expand needs a reference to expand")
			}

			extra, err := a.verificationOptions(cmd)
			if err != nil {
				return err
			}
			client, err := a.client(cmd, extra...)
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			a.printer.Progress().Step("verifying and expanding %s", reference)
			policyPath := a.setting(cmd, "policy", a.config.Policy)
			a.warnUnusedTrustMaterial(cmd, policyPath)

			result, err := client.Expand(ctx, devproof.ExpandRequest{
				Reference:     reference,
				Destination:   cmd.String("to"),
				RequireDigest: cmd.Bool(flagRequireDigest),
				PolicyPath:    policyPath,
			})
			if err != nil {
				return err
			}

			// Quiet output is the destination path: what a script does next
			// is operate on the files.
			return a.printer.Result("ExpandResult", result, result.Destination, func(w io.Writer) {
				Field(w, "destination", result.Destination)
				Field(w, "subject", result.SubjectDigest)
				Field(w, "tree digest", result.TreeDigest)
				Field(w, "files", fmt.Sprint(result.FileCount))
				Field(w, "bytes", fmt.Sprint(result.TotalBytes))
				if result.Verification != nil {
					Field(w, "integrity", result.Verification.Integrity.String())
					Field(w, "trust", result.Verification.Trust.String())
				}
			})
		},
	}
}

func (a *App) copyCommand() *cli.Command {
	return &cli.Command{
		Name:      "copy",
		Usage:     "copy a subject between registries or layouts",
		ArgsUsage: "SOURCE",
		Description: "The subject is verified at the source and republished under the same\n" +
			"rules as a build. Its digest is unchanged by definition: identity is a\n" +
			"function of content, and a repository name is not content.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "to", Usage: "destination", Required: true},
			&cli.StringFlag{Name: "tag", Usage: "tag to assign at the destination"},
			&cli.BoolFlag{Name: flagRequireDigest,
				Usage: "reject a source tag before fetching anything"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, cancel := a.withTimeout(ctx)
			defer cancel()

			source := cmd.Args().First()
			if source == "" {
				return usageError("copy needs a source reference")
			}

			client, err := a.client(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			a.printer.Progress().Step("copying %s", source)
			result, err := client.Copy(ctx, devproof.CopyRequest{
				Source:        source,
				Destination:   cmd.String("to"),
				Tag:           cmd.String("tag"),
				RequireDigest: cmd.Bool(flagRequireDigest),
			})
			if err != nil {
				return err
			}

			return a.printer.Result("CopyResult", result, result.Destination, func(w io.Writer) {
				Field(w, "subject", result.SubjectDigest)
				Field(w, "from", result.Source)
				Field(w, "to", result.Destination)
				if result.Tag != "" {
					Field(w, "tag", result.Tag)
				}
			})
		},
	}
}

func (a *App) inspectCommand() *cli.Command {
	return &cli.Command{
		Name:      "inspect",
		Usage:     "show subject, inventory, and evidence metadata",
		ArgsUsage: "REFERENCE_OR_PATH",
		Description: "Reports metadata without expanding anything and without any remote\n" +
			"mutation. Every fact is marked with how it was established, so a claim\n" +
			"is distinguishable from a proof.",
		Flags: append(verificationFlags(),
			&cli.BoolFlag{Name: "files", Usage: "include the file inventory"},
			&cli.BoolFlag{Name: "evidence", Usage: "include evidence summaries"},
			&cli.BoolFlag{Name: "evidence-content",
				Usage: "include full verified statements"},
		),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, cancel := a.withTimeout(ctx)
			defer cancel()

			target := cmd.Args().First()
			if target == "" {
				return usageError("inspect needs a reference or a file path")
			}

			extra, err := a.verificationOptions(cmd)
			if err != nil {
				return err
			}
			client, err := a.client(cmd, extra...)
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			request := devproof.InspectRequest{
				Files:           cmd.Bool("files"),
				Evidence:        cmd.Bool("evidence"),
				EvidenceContent: cmd.Bool("evidence-content"),
			}
			// A local path is a file that exists; anything else is a
			// reference. Deciding by existence rather than by syntax means a
			// directory named like a registry still inspects as a file.
			if looksLikePath(target) {
				request.Path = target
			} else {
				request.Reference = target
			}

			a.printer.Progress().Step("inspecting %s", target)
			result, err := client.Inspect(ctx, request)
			if err != nil {
				return err
			}

			return a.printer.Result("InspectResult", result, inspectQuiet(result), func(w io.Writer) {
				renderInspect(w, result)
			})
		},
	}
}

// warnUnusedTrustMaterial reports trust material that cannot take effect.
//
// Supplying --key or --trust-root and no policy is a reasonable thing to
// expect to work, and it does not: trust is evaluated only when a policy asks
// for it (DP-010), so the key is loaded and never consulted. Reporting
// "no verification policy was supplied" to someone who just supplied a key
// answers a question they did not ask. Saying which flag was ignored, and
// what to add, is the difference between a confusing result and an
// actionable one.
func (a *App) warnUnusedTrustMaterial(cmd *cli.Command, policyPath string) {
	if policyPath != "" {
		return
	}
	switch {
	case len(cmd.StringSlice("key")) > 0:
		a.printer.Warn("--key was supplied but no policy requires a signature, " +
			"so the key was not consulted; add --policy to evaluate trust")
	case cmd.String("trust-root") != "":
		a.printer.Warn("--trust-root was supplied but no policy requires a signature, " +
			"so it was not consulted; add --policy to evaluate trust")
	}
}

// verificationFlags are shared by every command that reads a subject.
func verificationFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{Name: "key",
			Usage: "trusted public key in PEM form; repeatable"},
		&cli.StringFlag{Name: "trust-root",
			Usage: "Sigstore trusted root for offline verification"},
		&cli.BoolFlag{Name: "offline",
			Usage: "prohibit network access; requires --trust-root"},
	}
}

func renderReport(w io.Writer, report *policy.Report) {
	Field(w, "subject", report.SubjectDigest)
	Field(w, "tree digest", report.TreeDigest)
	Field(w, "integrity", report.Integrity.String())
	Field(w, "trust", report.Trust.String())
	Field(w, "semantics", report.Semantics.String())
	if report.PolicyName != "" {
		Field(w, "policy", report.PolicyName)
		Field(w, "policy digest", report.PolicyDigest)
	}
	if len(report.AcceptedIdentities) > 0 {
		Field(w, "signed by", strings.Join(report.AcceptedIdentities, ", "))
	}
	if report.EvidenceStorage != "" {
		Field(w, "evidence", report.EvidenceStorage)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(w, "  %s\n", finding)
	}
	for _, rejected := range report.RejectedEvidence {
		fmt.Fprintf(w, "  ignored: %s\n", rejected)
	}
}

func renderInspect(w io.Writer, result *devproof.InspectResult) {
	switch {
	case result.Subject != nil:
		info := result.Subject
		Field(w, "kind", string(result.Kind))
		Field(w, "reference", info.Reference)
		Field(w, "subject", info.Digest)
		Field(w, "tree digest", info.TreeDigest)
		Field(w, "format", info.Format)
		Field(w, "confidence", string(info.Confidence))
		Field(w, "files", fmt.Sprint(info.FileCount))
		Field(w, "bytes", fmt.Sprint(info.TotalBytes))
		for _, file := range info.Files {
			fmt.Fprintf(w, "  %-10o %12d  %s\n", file.Mode, file.Size, file.Path)
		}
		for _, item := range info.Evidence {
			fmt.Fprintf(w, "  evidence %s (%s) signed by %s\n",
				item.Digest, item.Confidence, strings.Join(item.Identities, ", "))
		}
		for _, rejected := range info.RejectedEvidence {
			fmt.Fprintf(w, "  ignored: %s\n", rejected)
		}

	case result.Manifest != nil:
		info := result.Manifest
		Field(w, "kind", string(result.Kind))
		Field(w, "name", info.Name)
		Field(w, "digest", info.Digest)
		Field(w, "confidence", string(info.Confidence))
		for _, source := range info.Sources {
			fmt.Fprintf(w, "  %-16s %-8s %s\n", source.Name, source.Type, source.MountPath)
		}

	case result.Lock != nil:
		info := result.Lock
		Field(w, "kind", string(result.Kind))
		Field(w, "digest", info.Digest)
		Field(w, "manifest digest", info.ManifestDigest)
		Field(w, "tree digest", info.TreeDigest)
		Field(w, "confidence", string(info.Confidence))
		Field(w, "files", fmt.Sprint(info.FileCount))
		for _, source := range info.Sources {
			fmt.Fprintf(w, "  %-16s %-8s %s\n", source.Name, source.Type, source.TreeDigest)
		}
		for _, file := range info.Files {
			fmt.Fprintf(w, "  %-10o %12d  %s\n", file.Mode, file.Size, file.Path)
		}
	}
}

func inspectQuiet(result *devproof.InspectResult) string {
	switch {
	case result.Subject != nil:
		return result.Subject.Digest
	case result.Manifest != nil:
		return result.Manifest.Digest
	case result.Lock != nil:
		return result.Lock.Digest
	default:
		return ""
	}
}
