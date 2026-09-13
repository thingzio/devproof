// Package external implements devproof's source contract from outside the
// module, which is the only way to know that it can be.
//
// DP-009 promises registered source resolvers. The interface was written in
// terms of types under internal/, which Go forbids an external module from
// naming, so the extension point could be described and called and never
// implemented. Nothing inside the repository could catch that: every test
// there may name internal types.
package external

import (
	"bytes"
	"context"
	"io"

	"github.com/thingzio/devproof/pkg/bundle"
	"github.com/thingzio/devproof/pkg/source"
)

type Resolver struct{}

var _ source.Resolver = (*Resolver)(nil)

func (r *Resolver) Type() string { return "example.com/external" }

func (r *Resolver) Identity() source.Identity {
	return source.Identity{Name: "example.com/external", Version: "1"}
}

func (r *Resolver) Resolve(context.Context, source.ResolveRequest) (source.Snapshot, error) {
	content := []byte("hello\n")
	return &snapshot{
		content: content,
		records: []bundle.FileRecord{{
			Path:   bundle.Path("greeting.txt"),
			Mode:   bundle.ModeFile,
			Size:   int64(len(content)),
			Digest: bundle.DigestOf(content),
		}},
	}, nil
}

type snapshot struct {
	content []byte
	records []bundle.FileRecord
}

var _ source.Snapshot = (*snapshot)(nil)

func (s *snapshot) Records() []bundle.FileRecord { return s.records }

func (s *snapshot) Open(context.Context, bundle.Path) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

func (s *snapshot) Material() source.Material {
	return source.Material{
		Type:       "example.com/external",
		Resolver:   source.Identity{Name: "example.com/external", Version: "1"},
		TreeDigest: bundle.DigestOf(s.content),
	}
}

func (s *snapshot) Close() error { return nil }
