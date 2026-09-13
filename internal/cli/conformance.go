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
	"os"
	"strconv"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devproof/pkg/conformance"
	"github.com/thingzio/devproof/pkg/fault"
)

// conformanceResult is what the command reports.
//
// Deviations are named rather than counted: a list of what a structural pass
// tolerated is the only part of the output that tells somebody what to fix.
type conformanceResult struct {
	Level         string   `json:"level"`
	SubjectDigest string   `json:"subjectDigest"`
	TreeDigest    string   `json:"treeDigest"`
	FileCount     int64    `json:"fileCount"`
	TotalBytes    int64    `json:"totalBytes"`
	Deviations    []string `json:"deviations,omitempty"`
}

// conformanceCommand checks an artifact against the format specification.
//
// It is deliberately not part of verify. Verification asks whether an artifact
// is the one you wanted and whether you trust who produced it; this asks
// whether the bytes are what the specification describes, which is a question
// about an implementation rather than about an artifact's provenance. Anyone
// writing a second implementation needs the second question answerable on its
// own, with no policy, no evidence, and no network (DP-034).
func (a *App) conformanceCommand() *cli.Command {
	return &cli.Command{
		Name:      "conformance",
		Usage:     "check an artifact or vector set against the format specification",
		ArgsUsage: "LAYOUT_PATH",
		Description: "Reads the artifact with an independent implementation built from\n" +
			"docs/bundle-format.md, sharing no code with the writer. Levels:\n\n" +
			"  structure  intact, self-consistent, and safe to expand\n" +
			"  canonical  the only bytes a conforming writer produces for this tree\n" +
			"  bytes      identical to the published vectors in vectors/\n\n" +
			"A deviation above the requested level is reported rather than\n" +
			"discarded, so a structural pass still says what it tolerated.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "level", Value: "canonical",
				Usage: "structure, canonical, or bytes"},
			&cli.StringFlag{Name: "reference", Value: "",
				Usage: "tag or digest selecting the subject; required when the layout holds several"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			target := cmd.Args().First()
			if target == "" {
				return usageError("conformance needs a path to an OCI layout or a vector directory")
			}

			report, err := runConformance(target, cmd.String("level"), cmd.String("reference"))
			if err != nil {
				return err
			}

			result := conformanceResult{
				Level:         report.Level.String(),
				SubjectDigest: report.ManifestDigest,
				TreeDigest:    report.TreeDigest,
				FileCount:     report.FileCount,
				TotalBytes:    report.TotalSize,
				Deviations:    report.Deviations,
			}
			for _, note := range report.Deviations {
				a.printer.Warn("tolerated at this level: %s", note)
			}

			return a.printer.Result("ConformanceResult", result, result.SubjectDigest,
				func(w io.Writer) {
					Field(w, "level", result.Level)
					Field(w, "subject", result.SubjectDigest)
					Field(w, "tree", result.TreeDigest)
					Field(w, "files", strconv.FormatInt(result.FileCount, 10))
					Field(w, "bytes", strconv.FormatInt(result.TotalBytes, 10))
					Field(w, "deviations", strconv.Itoa(len(result.Deviations)))
				})
		},
	}
}

// runConformance dispatches on the requested level.
func runConformance(target, level, reference string) (*conformance.Report, error) {
	switch level {
	case "structure":
		return checked(conformance.VerifyLayout(target, reference, conformance.LevelStructure))
	case "canonical":
		return checked(conformance.VerifyLayout(target, reference, conformance.LevelCanonical))
	case "bytes":
		// A vector directory, not a layout: byte conformance is a claim about
		// what an encoder produced, so the thing being checked is the set of
		// files it wrote.
		return checked(conformance.VerifyVectors(os.DirFS(target)))
	default:
		return nil, usageError(fmt.Sprintf(
			"level %q is not one of structure, canonical, or bytes", level))
	}
}

// checked turns a conformance failure into an invalid-artifact fault.
//
// The package reports plain errors on purpose — it shares nothing with the rest
// of the codebase — so the mapping to an exit code happens here.
func checked(report *conformance.Report, err error) (*conformance.Report, error) {
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, "cli",
			"the artifact does not conform to the format specification", err)
	}
	return report, nil
}
