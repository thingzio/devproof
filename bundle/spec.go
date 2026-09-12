package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/thingzio/devproof/internal/fault"
)

const specOp = "bundle.spec"

// Built-in source types.
const (
	SourceTypePath = "path"
	SourceTypeGit  = "git"
)

// maxNameLength bounds a logical name. 63 characters matches the DNS label
// limit, which is the convention these names follow.
const maxNameLength = 63

// Spec is a bundle manifest: what a user intends to package.
//
// It records intent and may name mutable things — a branch, a moving tag, a
// local directory. Resolving those into something immutable is the lock's
// job, and keeping the two documents separate is what makes "what did you ask
// for" and "what did you get" independently reviewable (DP-004).
type Spec struct {
	APIVersion string       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string       `json:"kind" yaml:"kind"`
	Metadata   SpecMetadata `json:"metadata" yaml:"metadata"`
	Spec       SpecBody     `json:"spec" yaml:"spec"`
}

// SpecMetadata carries the bundle's logical name.
type SpecMetadata struct {
	// Name is a label for diagnostics and evidence. It does not affect
	// payload or subject identity: two bundles with the same content and
	// different names have the same digest (DP-002).
	Name string `json:"name" yaml:"name"`
}

// SpecBody holds the sources to compose.
type SpecBody struct {
	Sources []SourceSpec `json:"sources" yaml:"sources"`
}

// SourceSpec declares one source.
type SourceSpec struct {
	Name      string `json:"name" yaml:"name"`
	Type      string `json:"type" yaml:"type"`
	MountPath string `json:"mountPath,omitempty" yaml:"mountPath,omitempty"`

	Include []string `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty" yaml:"exclude,omitempty"`

	// Config is resolver-specific.
	//
	// It is held untyped until a registered resolver decodes it, so an
	// unknown field in a resolver's config is that resolver's error to
	// report rather than something the loader must know about in advance.
	// A map rather than raw bytes because the manifest digest is computed
	// over canonical JSON of the typed model, and raw YAML has no canonical
	// form.
	Config map[string]any `json:"config,omitempty" yaml:"config,omitempty"`
}

// ParseSpec decodes and validates a manifest from YAML or JSON.
//
// Decoding is strict in both directions that matter: an unknown field is an
// error, and so is a duplicate mapping key. A manifest is a security-relevant
// document, and a reader that silently ignores a field it does not recognize
// will happily build something other than what was written.
func ParseSpec(data []byte) (*Spec, error) {
	if len(data) == 0 {
		return nil, fault.New(fault.CodeInvalidInput, specOp, "manifest is empty")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var spec Spec
	if err := decoder.Decode(&spec); err != nil {
		return nil, fault.Wrap(fault.CodeInvalidInput, specOp, "decoding manifest", err)
	}

	// A second document would be silently ignored by most YAML readers.
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fault.New(fault.CodeInvalidInput, specOp,
			"manifest contains more than one YAML document")
	}

	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return &spec, nil
}

// Validate checks the manifest's structure.
func (s *Spec) Validate() error {
	if s.APIVersion != APIVersionV1Alpha1 {
		return fault.New(fault.CodeUnsupportedVersion, specOp,
			fmt.Sprintf("manifest apiVersion %q is not supported; this build reads %q",
				s.APIVersion, APIVersionV1Alpha1))
	}
	if s.Kind != KindBundle {
		return fault.New(fault.CodeInvalidInput, specOp,
			fmt.Sprintf("manifest kind is %q, want %q", s.Kind, KindBundle))
	}
	if err := ValidateName(s.Metadata.Name, "metadata.name"); err != nil {
		return err
	}
	if len(s.Spec.Sources) == 0 {
		return fault.New(fault.CodeInvalidInput, specOp, "manifest declares no sources")
	}

	seen := make(map[string]struct{}, len(s.Spec.Sources))
	for i := range s.Spec.Sources {
		source := &s.Spec.Sources[i]
		if err := source.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[source.Name]; duplicate {
			return fault.New(fault.CodeInvalidInput, specOp,
				fmt.Sprintf("two sources are named %q", source.Name))
		}
		seen[source.Name] = struct{}{}
	}
	return nil
}

// Validate checks one source declaration.
func (s *SourceSpec) Validate() error {
	if err := ValidateName(s.Name, "source name"); err != nil {
		return err
	}
	if err := validateSourceType(s.Type); err != nil {
		return err
	}
	if _, err := NormalizeMountPath(s.MountPath); err != nil {
		return err
	}
	// Compiling the patterns here rather than at resolve time means a typo in
	// a manifest is reported when the manifest is read, not after a clone.
	if _, err := NewPatternSet(s.Include, s.Exclude); err != nil {
		return err
	}
	return nil
}

// validateSourceType accepts a built-in short name or a domain-qualified
// extension type.
//
// Requiring a domain in an extension type keeps the short namespace reserved
// for DevProof: an application cannot register something called "git" and
// have manifests silently mean it.
func validateSourceType(sourceType string) error {
	switch sourceType {
	case "":
		return fault.New(fault.CodeInvalidInput, specOp, "source has no type")
	case SourceTypePath, SourceTypeGit:
		return nil
	}
	domain, name, ok := strings.Cut(sourceType, "/")
	if !ok || domain == "" || name == "" || !strings.Contains(domain, ".") {
		return fault.New(fault.CodeUnsupportedSource, specOp,
			fmt.Sprintf("source type %q is not built in; an extension type must be "+
				"domain-qualified, such as storage.example.com/object", sourceType))
	}
	return nil
}

// ValidateName checks a logical name: lowercase ASCII letters, digits, and
// hyphens, starting and ending alphanumeric.
//
// The grammar is restrictive because these names appear in diagnostics,
// evidence, and error messages, where a name containing a newline or a
// control character is a way to forge output.
func ValidateName(name, field string) error {
	reject := func(msg string) error {
		return fault.New(fault.CodeInvalidInput, specOp, fmt.Sprintf("%s %s", field, msg))
	}

	switch {
	case name == "":
		return reject("is required")
	case len(name) > maxNameLength:
		return reject(fmt.Sprintf("is %d characters, the maximum is %d", len(name), maxNameLength))
	}

	for i := range len(name) {
		c := name[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLower && !isDigit && c != '-' {
			return reject(fmt.Sprintf("contains %q; use lowercase letters, digits, and hyphens",
				string(c)))
		}
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return reject("must begin and end with a letter or digit")
	}
	return nil
}

// NormalizeMountPath canonicalizes a mount path. Empty and "." both mean the
// bundle root.
func NormalizeMountPath(mount string) (string, error) {
	if mount == "" || mount == "." {
		return "", nil
	}
	if strings.HasPrefix(mount, "/") {
		return "", fault.New(fault.CodeInvalidInput, specOp,
			fmt.Sprintf("mountPath %q must be relative", mount))
	}
	segments := strings.Split(mount, "/")
	for _, segment := range segments {
		switch segment {
		case "", ".", "..":
			return "", fault.New(fault.CodeInvalidInput, specOp,
				fmt.Sprintf("mountPath %q must not contain empty, ., or .. segments", mount))
		}
	}
	return mount, nil
}

// Normalized returns a copy with set-like fields canonicalized.
//
// The manifest digest is computed over this form, so that YAML spelling, key
// order, comments, and the order of an include list cannot change it. Two
// manifests that mean the same thing hash the same (DP-004).
func (s *Spec) Normalized() *Spec {
	out := &Spec{
		APIVersion: s.APIVersion,
		Kind:       s.Kind,
		Metadata:   s.Metadata,
	}
	out.Spec.Sources = make([]SourceSpec, len(s.Spec.Sources))
	copy(out.Spec.Sources, s.Spec.Sources)

	for i := range out.Spec.Sources {
		source := &out.Spec.Sources[i]
		source.Include = NormalizePatterns(source.Include)
		source.Exclude = NormalizePatterns(source.Exclude)
		// An omitted mountPath and an explicit "." are the same instruction.
		if normalized, err := NormalizeMountPath(source.MountPath); err == nil {
			source.MountPath = normalized
		}
	}
	slices.SortFunc(out.Spec.Sources, func(a, b SourceSpec) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// SourceByName returns a source declaration.
func (s *Spec) SourceByName(name string) (*SourceSpec, bool) {
	for i := range s.Spec.Sources {
		if s.Spec.Sources[i].Name == name {
			return &s.Spec.Sources[i], true
		}
	}
	return nil, false
}

// DecodeConfig strictly decodes a resolver's configuration into target.
//
// The round trip through JSON is deliberate. It gives resolvers ordinary
// struct tags and, more importantly, DisallowUnknownFields: a config key a
// resolver does not recognize is a mistake the author should hear about, not
// something to drop on the floor.
func DecodeConfig(config map[string]any, target any) error {
	encoded, err := json.Marshal(config)
	if err != nil {
		return fault.Wrap(fault.CodeInvalidInput, specOp, "re-encoding source config", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fault.Wrap(fault.CodeInvalidInput, specOp, "decoding source config", err)
	}
	return nil
}
