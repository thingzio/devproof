package oci

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"sync"

	"github.com/thingzio/devproof/artifact"
	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
)

const layoutTransportOp = "oci.layout.transport"

// LayoutTransport exposes local OCI image layouts through the same contract
// as a registry.
//
// Having one contract is what keeps the publication rules — blobs before the
// manifest, read back before tagging, tag last — in one place. A local
// destination that had its own code path would be the one where those rules
// quietly diverged, and it is the path most people develop against.
type LayoutTransport struct {
	mu      sync.Mutex
	layouts map[string]*Layout
}

var _ artifact.Transport = (*LayoutTransport)(nil)

// NewLayoutTransport returns a transport for local layouts.
func NewLayoutTransport() *LayoutTransport {
	return &LayoutTransport{layouts: make(map[string]*Layout)}
}

func (t *LayoutTransport) Scheme() string { return artifact.SchemeLayout }

// layout opens the layout a reference names, creating it when create is set.
func (t *LayoutTransport) layout(ref artifact.Reference, create bool) (*Layout, error) {
	if ref.Scheme != artifact.SchemeLayout {
		return nil, fault.New(fault.CodeInvalidInput, layoutTransportOp,
			fmt.Sprintf("reference scheme %q is not a layout reference", ref.Scheme))
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if cached, ok := t.layouts[ref.Path]; ok {
		return cached, nil
	}

	layout, err := Open(ref.Path)
	if err != nil {
		if !create {
			return nil, err
		}
		// A path that is not yet a layout is the ordinary case for a build
		// destination, not a failure.
		layout, err = Create(ref.Path)
		if err != nil {
			return nil, err
		}
	}
	t.layouts[ref.Path] = layout
	return layout, nil
}

// Resolve freezes a reference to one descriptor.
func (t *LayoutTransport) Resolve(_ context.Context, ref artifact.Reference) (artifact.Descriptor, error) {
	layout, err := t.layout(ref, false)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	target := ref.Target()
	if target == "" {
		return artifact.Descriptor{}, fault.New(fault.CodeInvalidInput, layoutTransportOp,
			"reference names neither a tag nor a digest")
	}

	item, err := layout.FindManifest(target)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	return item.Descriptor(), nil
}

// Fetch returns the content a descriptor names.
func (t *LayoutTransport) Fetch(_ context.Context, ref artifact.Reference, target artifact.Descriptor) (io.ReadCloser, error) {
	layout, err := t.layout(ref, false)
	if err != nil {
		return nil, err
	}
	if validateErr := target.Validate(); validateErr != nil {
		return nil, validateErr
	}
	digest, err := target.ParsedDigest()
	if err != nil {
		return nil, err
	}

	reader, _, err := layout.OpenBlob(digest)
	return reader, err
}

// Push stores content under its descriptor.
func (t *LayoutTransport) Push(_ context.Context, ref artifact.Reference, target artifact.Descriptor, content io.Reader) error {
	layout, err := t.layout(ref, true)
	if err != nil {
		return err
	}
	if validateErr := target.Validate(); validateErr != nil {
		return validateErr
	}

	// Buffered because the layout is content-addressed and cannot name a
	// blob before it knows its digest. The descriptor's declared size bounds
	// the read, so a reader that claims to be small and is not cannot force
	// an unbounded allocation.
	body, err := io.ReadAll(io.LimitReader(content, target.Size+1))
	if err != nil {
		return fault.Wrap(fault.CodeInternal, layoutTransportOp, "reading content to store", err)
	}
	if int64(len(body)) != target.Size {
		return fault.New(fault.CodeDigestMismatch, layoutTransportOp,
			fmt.Sprintf("content is %d bytes, the descriptor declares %d", len(body), target.Size))
	}
	// Verified before it is written, so a blob can never be filed under a
	// digest it does not have.
	if verifyErr := target.VerifyContent(body); verifyErr != nil {
		return verifyErr
	}

	_, err = layout.PutBlob(body)
	return err
}

// Tag assigns a mutable name to an already-stored manifest.
func (t *LayoutTransport) Tag(_ context.Context, ref artifact.Reference, target artifact.Descriptor, tag string) error {
	layout, err := t.layout(ref, true)
	if err != nil {
		return err
	}
	return layout.AddManifest(target, bundle.MediaTypeArtifactV1, tag)
}

// Record registers a manifest in the index without assigning a tag.
//
// A layout has no way to enumerate manifests other than its index, so an
// untagged subject still has to be recorded or it would be unreachable. This
// is layout-specific: a registry keeps a manifest addressable by digest with
// no index entry at all.
func (t *LayoutTransport) Record(ref artifact.Reference, target artifact.Descriptor) error {
	layout, err := t.layout(ref, true)
	if err != nil {
		return err
	}
	return layout.AddManifest(target, bundle.MediaTypeArtifactV1, "")
}

// Close releases every layout this transport opened.
func (t *LayoutTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var errs []error
	for path, layout := range t.layouts {
		if err := layout.Close(); err != nil {
			errs = append(errs, fault.Wrap(fault.CodeInternal, layoutTransportOp,
				"closing layout "+path, err))
		}
	}
	t.layouts = make(map[string]*Layout)
	return stderrors.Join(errs...)
}
