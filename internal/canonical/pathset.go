package canonical

import (
	"fmt"
	"slices"

	"github.com/thingzio/devproof/internal/fault"
)

const setOp = "canonical.pathset"

type nodeKind uint8

const (
	nodeFile nodeKind = iota + 1
	nodeDir
)

// PathSet accumulates canonical paths and rejects any tree a consumer could
// materialize two different ways.
//
// Three shapes are refused, all for the same reason: the result would depend
// on the extractor rather than on the bundle.
//
//   - Two files at one path, or at paths that fold together. Equal bytes do
//     not help; ownership would still be ambiguous (DP-011).
//   - A file whose path is a directory in another entry, in either order.
//   - Any of the above across case, since a case-insensitive filesystem
//     merges them on arrival.
//
// The zero value is ready to use.
type PathSet struct {
	nodes map[string]nodeKind
	fold  map[string]string
	files []Path
}

func (s *PathSet) lazyInit() {
	if s.nodes == nil {
		s.nodes = make(map[string]nodeKind)
		s.fold = make(map[string]string)
	}
}

// Add records p, deriving its parent directories.
//
// Callers that need a deterministic *message* when a tree has several
// collisions should add paths in sorted order. The failure itself is
// order-independent: a colliding tree is rejected whatever order it arrives
// in, which is the property DP-011 requires.
func (s *PathSet) Add(p Path) error {
	s.lazyInit()

	path := string(p)
	if path == "" {
		return fault.New(fault.CodeUnsafePath, setOp, "path must not be empty")
	}

	for _, dir := range p.Parents() {
		switch s.nodes[dir] {
		case nodeFile:
			return fault.New(fault.CodePathCollision, setOp,
				fmt.Sprintf("path requires %q to be a directory, but it is also a file", dir)).
				WithPath(path)
		case nodeDir:
			// Already derived, and its fold key already claimed by itself.
		default:
			if err := s.claimFold(dir, path); err != nil {
				return err
			}
			s.nodes[dir] = nodeDir
		}
	}

	switch s.nodes[path] {
	case nodeDir:
		return fault.New(fault.CodePathCollision, setOp,
			"path is a file here and a directory elsewhere in the tree").WithPath(path)
	case nodeFile:
		return fault.New(fault.CodePathCollision, setOp,
			"duplicate path; two sources cannot own one destination").WithPath(path)
	default:
	}

	if err := s.claimFold(path, path); err != nil {
		return err
	}
	s.nodes[path] = nodeFile
	s.files = append(s.files, p)
	return nil
}

// claimFold records that node owns its case-folded key, or reports the
// earlier node that already owns it. context names the path being added, so
// that a collision discovered while deriving a parent still points at the
// entry that triggered it.
func (s *PathSet) claimFold(node, context string) error {
	key := foldString(node)
	prev, ok := s.fold[key]
	switch {
	case !ok:
		s.fold[key] = node
		return nil
	case prev == node:
		return nil
	default:
		return fault.New(fault.CodePathCollision, setOp,
			fmt.Sprintf("%q and %q differ only by case and would collide on a "+
				"case-insensitive filesystem", prev, node)).
			WithPath(context)
	}
}

// HasFile reports whether p was added as a file.
func (s *PathSet) HasFile(p Path) bool { return s.nodes[string(p)] == nodeFile }

// Len reports how many files were added.
func (s *PathSet) Len() int { return len(s.files) }

// Files returns every added path sorted by canonical UTF-8 bytes, which is
// the order the tree digest and the tar stream require.
func (s *PathSet) Files() []Path {
	out := slices.Clone(s.files)
	slices.Sort(out)
	return out
}

// Directories returns the derived parent directories sorted by canonical
// UTF-8 bytes, which places every parent before its children.
func (s *PathSet) Directories() []string {
	out := make([]string, 0, len(s.nodes)-len(s.files))
	for path, kind := range s.nodes {
		if kind == nodeDir {
			out = append(out, path)
		}
	}
	slices.Sort(out)
	return out
}
