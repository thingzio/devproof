package canonical

import (
	"fmt"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const configOp = "canonical.config"

// BuildConfig produces the config blob describing records.
//
// records must already be sorted and validated; WriteTreeRecords is called to
// derive the tree digest, so an unsorted or malformed set fails here rather
// than producing a config that describes a tree nobody can reproduce.
func BuildConfig(records []FileRecord) (*bundle.Config, error) {
	treeDigest, err := TreeDigest(records)
	if err != nil {
		return nil, err
	}

	cfg := &bundle.Config{
		SchemaVersion: bundle.ConfigSchemaVersion,
		Format:        bundle.FormatV1,
		TreeDigest:    treeDigest.String(),
		FileCount:     int64(len(records)),
		Files:         make([]bundle.ConfigFile, 0, len(records)),
	}

	for _, rec := range records {
		cfg.TotalSize += rec.Size
		cfg.Files = append(cfg.Files, bundle.ConfigFile{
			Path:   string(rec.Path),
			Mode:   rec.Mode,
			Size:   rec.Size,
			Digest: rec.Digest.String(),
		})
	}

	// Validating what was just built is not redundant: it is the assertion
	// that the two independent descriptions of the same tree — the record
	// stream and the config — agree before either is published.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ConfigRecords converts a validated config back into file records.
//
// This is the verification direction: a config fetched from a registry is
// turned into records so its tree digest can be recomputed and compared
// against the one the config claims.
func ConfigRecords(cfg *bundle.Config) ([]FileRecord, error) {
	records := make([]FileRecord, 0, len(cfg.Files))

	for i := range cfg.Files {
		file := &cfg.Files[i]

		digest, err := bundle.ParseDigest(file.Digest)
		if err != nil {
			return nil, fault.Wrap(fault.CodeInvalidArtifact, configOp,
				"config entry digest is invalid", err).WithPath(file.Path)
		}
		records = append(records, FileRecord{
			Path:   Path(file.Path),
			Mode:   file.Mode,
			Size:   file.Size,
			Digest: digest,
		})
	}
	return records, nil
}

// EncodeConfig renders cfg as canonical JSON and returns the bytes with their
// digest.
func EncodeConfig(cfg *bundle.Config) (Digest, []byte, error) {
	return JSONDigest(cfg)
}

// VerifyConfigTreeDigest recomputes the tree digest from a config's own
// inventory and compares it against the digest the config states.
//
// The two can disagree only if the config was tampered with, so a mismatch is
// reported as such rather than as a generic validation failure.
func VerifyConfigTreeDigest(cfg *bundle.Config) (Digest, error) {
	records, err := ConfigRecords(cfg)
	if err != nil {
		return Digest{}, err
	}

	recomputed, err := TreeDigest(records)
	if err != nil {
		return Digest{}, err
	}

	stated, err := bundle.ParseDigest(cfg.TreeDigest)
	if err != nil {
		return Digest{}, fault.Wrap(fault.CodeInvalidArtifact, configOp,
			"config tree digest is invalid", err)
	}
	if recomputed != stated {
		return Digest{}, fault.New(fault.CodeDigestMismatch, configOp,
			fmt.Sprintf("config states tree digest %s but its inventory produces %s",
				stated, recomputed))
	}
	return recomputed, nil
}
