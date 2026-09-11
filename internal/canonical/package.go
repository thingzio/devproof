package canonical

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const packageOp = "canonical.package"

// ContentSource supplies the bytes for a canonical file record.
//
// Packaging reads only through this interface, and only for paths that appear
// in the inventory it was given. That is what keeps the packager away from a
// live filesystem: a resolver hands it a frozen snapshot, and there is no API
// here through which it could reach anything else.
type ContentSource interface {
	Open(ctx context.Context, path Path) (io.ReadCloser, error)
}

// Package encodes records into a complete bundle subject, streaming the
// compressed layer to layerOut.
//
// The work happens in one pass over the content so that hashing, archiving,
// and compressing all see the same bytes. Anything else would leave a window
// in which the layer describes content the config never saw.
func Package(ctx context.Context, records []FileRecord, src ContentSource, layerOut io.Writer) (*Subject, error) {
	// Rebuilding the path set from the inventory re-runs collision detection
	// on the exact records about to be encoded, and derives the directories
	// rather than trusting a caller to have listed them correctly.
	var paths PathSet
	for _, rec := range records {
		if err := paths.Add(rec.Path); err != nil {
			return nil, err
		}
	}

	cfg, err := BuildConfig(records)
	if err != nil {
		return nil, err
	}
	configDigest, configBytes, err := EncodeConfig(cfg)
	if err != nil {
		return nil, err
	}

	layerDigest, layerSize, err := writeLayer(ctx, records, paths.Directories(), src, layerOut)
	if err != nil {
		return nil, err
	}

	treeDigest, err := ParseDigest(cfg.TreeDigest)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, packageOp, "config tree digest is invalid", err)
	}

	manifest := artifact.NewManifest(
		artifact.Descriptor{
			MediaType: bundle.MediaTypeConfigV1,
			Digest:    configDigest.String(),
			Size:      int64(len(configBytes)),
		},
		artifact.Descriptor{
			MediaType: bundle.MediaTypeLayerV1,
			Digest:    layerDigest.String(),
			Size:      layerSize,
		},
	)
	manifestDigest, manifestBytes, err := EncodeManifest(manifest)
	if err != nil {
		return nil, err
	}

	return &Subject{
		Manifest:       manifest,
		ManifestBytes:  manifestBytes,
		ManifestDigest: manifestDigest,
		Config:         cfg,
		ConfigBytes:    configBytes,
		ConfigDigest:   configDigest,
		LayerDigest:    layerDigest,
		LayerSize:      layerSize,
		TreeDigest:     treeDigest,
	}, nil
}

// writeLayer emits the canonical tar stream through the canonical gzip
// encoder, hashing and counting the compressed result as it goes.
func writeLayer(
	ctx context.Context,
	records []FileRecord,
	directories []string,
	src ContentSource,
	out io.Writer,
) (Digest, int64, error) {

	hasher := sha256.New()
	counter := &countingWriter{}
	gzipWriter, err := NewGzipWriter(io.MultiWriter(out, hasher, counter))
	if err != nil {
		return Digest{}, 0, err
	}
	tarWriter := NewTarWriter(gzipWriter)

	// Directories are emitted first and in sorted order, which places every
	// parent before its first child because a parent is a byte-prefix of its
	// children.
	for _, dir := range directories {
		if err := fault.FromContext(ctx, packageOp, "packaging canceled"); err != nil {
			return Digest{}, 0, err
		}
		if err := tarWriter.WriteDirectory(dir); err != nil {
			return Digest{}, 0, err
		}
	}

	for _, rec := range records {
		if err := fault.FromContext(ctx, packageOp, "packaging canceled"); err != nil {
			return Digest{}, 0, err
		}
		if err := writeOneFile(ctx, tarWriter, rec, src); err != nil {
			return Digest{}, 0, err
		}
	}

	if err := tarWriter.Close(); err != nil {
		return Digest{}, 0, err
	}
	if err := gzipWriter.Close(); err != nil {
		return Digest{}, 0, err
	}

	return digestFrom(hasher), counter.n, nil
}

func writeOneFile(ctx context.Context, tw *TarWriter, rec FileRecord, src ContentSource) (retErr error) {
	content, err := src.Open(ctx, rec.Path)
	if err != nil {
		return fault.Wrap(fault.CodeSourceResolution, packageOp,
			"opening snapshot content", err).WithPath(string(rec.Path))
	}
	defer func() {
		if closeErr := content.Close(); closeErr != nil && retErr == nil {
			retErr = fault.Wrap(fault.CodeInternal, packageOp,
				"closing snapshot content", closeErr).WithPath(string(rec.Path))
		}
	}()

	// WriteFile hashes as it copies and rejects content that disagrees with
	// the record, so a source that changed after it was inventoried fails
	// here rather than producing a layer at odds with its own config.
	return tw.WriteFile(rec, content)
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// VerifySubject re-derives a subject's identity from its own blobs.
//
// It is the read-side counterpart of Package: given the bytes a registry
// served, it establishes that the manifest, config, and layer describe one
// consistent artifact before any of it is trusted or written to disk.
func VerifySubject(manifestBytes, configBytes []byte, layerSize int64, layerDigest Digest) (*Subject, error) {
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}

	manifestDigest := DigestOf(manifestBytes)

	if configErr := manifest.Config.VerifyContent(configBytes); configErr != nil {
		return nil, configErr
	}

	cfg, err := bundle.ParseConfig(configBytes)
	if err != nil {
		return nil, err
	}

	treeDigest, err := VerifyConfigTreeDigest(cfg)
	if err != nil {
		return nil, err
	}

	layer, err := manifest.Layer()
	if err != nil {
		return nil, err
	}
	statedLayerDigest, err := layer.ParsedDigest()
	if err != nil {
		return nil, fault.Wrap(fault.CodeInvalidArtifact, packageOp, "layer digest is invalid", err)
	}
	if statedLayerDigest != layerDigest {
		return nil, fault.New(fault.CodeDigestMismatch, packageOp,
			fmt.Sprintf("layer digest is %s, manifest declares %s", layerDigest, statedLayerDigest))
	}
	if layer.Size != layerSize {
		return nil, fault.New(fault.CodeDigestMismatch, packageOp,
			fmt.Sprintf("layer is %d bytes, manifest declares %d", layerSize, layer.Size))
	}

	return &Subject{
		Manifest:       manifest,
		ManifestBytes:  manifestBytes,
		ManifestDigest: manifestDigest,
		Config:         cfg,
		ConfigBytes:    configBytes,
		ConfigDigest:   DigestOf(configBytes),
		LayerDigest:    layerDigest,
		LayerSize:      layerSize,
		TreeDigest:     treeDigest,
	}, nil
}
