package bundle

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/thingzio/devproof/internal/fault"
)

const patternOp = "bundle.pattern"

// doubleStar matches zero or more complete path segments.
const doubleStar = "**"

// Pattern selects source-relative paths.
//
// The syntax is deliberately small: `*` for non-separator runs, `?` for one
// non-separator character, `[a-z]` classes, and `**` for whole segments.
// There is no negation, no ordering significance, and no .gitignore
// inheritance. Every one of those would make selection depend on the order
// rules were written, and DP-011 requires that a manifest's meaning not
// depend on how it was arranged.
type Pattern struct {
	raw      string
	segments []string
}

// ParsePattern compiles a selection pattern.
func ParsePattern(raw string) (*Pattern, error) {
	reject := func(msg string) error {
		return fault.New(fault.CodeInvalidInput, patternOp,
			fmt.Sprintf("selection pattern %q %s", raw, msg))
	}

	if raw == "" {
		return nil, reject("is empty")
	}
	if strings.HasPrefix(raw, "/") {
		return nil, reject("must be relative")
	}

	segments := strings.Split(raw, "/")
	for _, segment := range segments {
		switch segment {
		case "":
			return nil, reject("contains an empty segment")
		case ".":
			return nil, reject("contains a . segment")
		case "..":
			// A pattern that walks out of the selected root would select
			// material the manifest never named.
			return nil, reject("escapes the selected root")
		case doubleStar:
			continue
		}
		if strings.Contains(segment, doubleStar) {
			return nil, reject("uses ** as part of a segment; it must be a segment on its own")
		}
		// path.Match validates the class syntax. Segments never contain a
		// separator, so its separator handling is not in play.
		if _, err := path.Match(segment, ""); err != nil {
			return nil, fault.Wrap(fault.CodeInvalidInput, patternOp,
				fmt.Sprintf("selection pattern %q is malformed", raw), err)
		}
	}
	return &Pattern{raw: raw, segments: segments}, nil
}

// String returns the pattern as written.
func (p *Pattern) String() string { return p.raw }

// Match reports whether p selects a source-relative path.
func (p *Pattern) Match(candidate string) bool {
	return matchSegments(p.segments, strings.Split(candidate, "/"))
}

// matchSegments matches a segmented pattern against a segmented path.
//
// The table is what keeps `**` affordable. A recursive expansion is the
// obvious implementation and is exponential on a pattern like `**/**/**/x`,
// which is a denial-of-service vector in a document a source repository can
// supply. This is O(len(pattern) x len(path)) regardless.
func matchSegments(pattern, candidate []string) bool {
	// reachable[j] reports whether the first j path segments can be consumed
	// by the pattern segments processed so far.
	reachable := make([]bool, len(candidate)+1)
	reachable[0] = true

	for _, segment := range pattern {
		next := make([]bool, len(candidate)+1)

		if segment == doubleStar {
			// ** consumes any number of segments, so once a position is
			// reachable every later position is too.
			carried := false
			for j := range len(candidate) + 1 {
				carried = carried || reachable[j]
				next[j] = carried
			}
		} else {
			for j := range len(candidate) {
				if !reachable[j] {
					continue
				}
				if ok, err := path.Match(segment, candidate[j]); err == nil && ok {
					next[j+1] = true
				}
			}
		}
		reachable = next
	}
	return reachable[len(candidate)]
}

// PatternSet is a source's include and exclude rules.
//
// Include and exclude are sets, not ordered lists: a path is selected when it
// matches any include and no exclude. Because neither list has precedence,
// reordering a manifest cannot change what it selects.
type PatternSet struct {
	include []*Pattern
	exclude []*Pattern
}

// NewPatternSet compiles include and exclude rules.
//
// An absent include list means `**`, which selects everything. Spelling the
// default explicitly means there is no separate "no filter" code path whose
// behavior could drift from the filtered one.
func NewPatternSet(include, exclude []string) (*PatternSet, error) {
	set := &PatternSet{}

	if len(include) == 0 {
		include = []string{doubleStar}
	}
	for _, raw := range include {
		compiled, err := ParsePattern(raw)
		if err != nil {
			return nil, err
		}
		set.include = append(set.include, compiled)
	}
	for _, raw := range exclude {
		compiled, err := ParsePattern(raw)
		if err != nil {
			return nil, err
		}
		set.exclude = append(set.exclude, compiled)
	}
	return set, nil
}

// Selects reports whether a source-relative path survives filtering.
func (s *PatternSet) Selects(candidate string) bool {
	matched := false
	for _, pattern := range s.include {
		if pattern.Match(candidate) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, pattern := range s.exclude {
		if pattern.Match(candidate) {
			return false
		}
	}
	return true
}

// NormalizePatterns returns a sorted, de-duplicated copy.
//
// Patterns are a set, so the lock records them in a canonical order. Without
// this, reordering a manifest's include list would change the lock digest
// while selecting exactly the same files.
func NormalizePatterns(patterns []string) []string {
	if len(patterns) == 0 {
		return nil
	}
	out := slices.Clone(patterns)
	slices.Sort(out)
	return slices.Compact(out)
}
