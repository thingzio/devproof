package canonical

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	stderrors "errors"
	"io"
	"strings"
	"testing"

	"github.com/thingzio/devproof/bundle"
	"github.com/thingzio/devproof/internal/fault"
	"github.com/thingzio/devproof/internal/golden"
)

// entry is a fixture file: content plus the record describing it.
type entry struct {
	path string
	mode uint32
	data string
}

func (e entry) record() FileRecord {
	return FileRecord{
		Path:   Path(e.path),
		Mode:   e.mode,
		Size:   int64(len(e.data)),
		Digest: sha256.Sum256([]byte(e.data)),
	}
}

// writeTar emits dirs then entries, in the order given.
func writeTar(t *testing.T, dirs []string, entries []entry) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := NewTarWriter(&buf)
	for _, dir := range dirs {
		if err := w.WriteDirectory(dir); err != nil {
			t.Fatalf("WriteDirectory(%q): %v", dir, err)
		}
	}
	for _, e := range entries {
		if err := w.WriteFile(e.record(), strings.NewReader(e.data)); err != nil {
			t.Fatalf("WriteFile(%q): %v", e.path, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

// The stream must be readable by an ordinary tar implementation. A canonical
// encoding that only DevProof can read would defeat DP-006's whole point,
// which is that a generic OCI consumer can materialize the layer.
func TestTarIsReadableByStandardLibrary(t *testing.T) {
	t.Parallel()

	entries := []entry{
		{"README.md", bundle.ModeFile, "hello world\n"},
		{"app/config/service.yaml", bundle.ModeFile, "a: 1\n"},
		{"app/scripts/run.sh", bundle.ModeExecutable, "#!/bin/sh\necho hi\n"},
		{"empty", bundle.ModeFile, ""},
		{"café/naïve.txt", bundle.ModeFile, "utf8"},
	}
	dirs := []string{"app", "app/config", "app/scripts", "café"}

	r := tar.NewReader(bytes.NewReader(writeTar(t, dirs, entries)))

	var sawFiles []string
	var sawDirs []string
	for {
		hdr, err := r.Next()
		if stderrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("standard reader rejected our stream: %v", err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			sawDirs = append(sawDirs, strings.TrimSuffix(hdr.Name, "/"))
			if hdr.Mode != int64(bundle.ModeDirectory) {
				t.Errorf("directory %q mode = %#o, want %#o", hdr.Name, hdr.Mode, bundle.ModeDirectory)
			}
		case tar.TypeReg:
			sawFiles = append(sawFiles, hdr.Name)
			body, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("reading %q: %v", hdr.Name, err)
			}
			want := findEntry(entries, hdr.Name)
			if string(body) != want.data {
				t.Errorf("%q content = %q, want %q", hdr.Name, body, want.data)
			}
			if hdr.Mode != int64(want.mode) {
				t.Errorf("%q mode = %#o, want %#o", hdr.Name, hdr.Mode, want.mode)
			}
		default:
			t.Errorf("unexpected entry type %q for %q", hdr.Typeflag, hdr.Name)
		}

		// Every one of these would otherwise make the same tree encode
		// differently depending on who built it.
		if hdr.Uid != 0 || hdr.Gid != 0 {
			t.Errorf("%q has uid/gid %d/%d, want 0/0", hdr.Name, hdr.Uid, hdr.Gid)
		}
		if hdr.Uname != "" || hdr.Gname != "" {
			t.Errorf("%q has uname/gname %q/%q, want empty", hdr.Name, hdr.Uname, hdr.Gname)
		}
		if !hdr.ModTime.IsZero() && hdr.ModTime.Unix() != 0 {
			t.Errorf("%q mtime = %v, want the epoch", hdr.Name, hdr.ModTime)
		}
		if !hdr.AccessTime.IsZero() {
			t.Errorf("%q carries an atime; v1 omits it", hdr.Name)
		}
		if !hdr.ChangeTime.IsZero() {
			t.Errorf("%q carries a ctime; v1 omits it", hdr.Name)
		}
		if hdr.Linkname != "" {
			t.Errorf("%q has a linkname", hdr.Name)
		}
	}

	if len(sawFiles) != len(entries) {
		t.Errorf("read %d files, wrote %d", len(sawFiles), len(entries))
	}
	if len(sawDirs) != len(dirs) {
		t.Errorf("read %d directories, wrote %d", len(sawDirs), len(dirs))
	}
}

func findEntry(entries []entry, name string) entry {
	for _, e := range entries {
		if e.path == name {
			return e
		}
	}
	return entry{}
}

// A path beyond the USTAR name field is the one case that produces a PAX
// header, so the standard reader must recover the full path from it.
func TestTarLongPathUsesPAXAndRoundTrips(t *testing.T) {
	t.Parallel()

	longPath := strings.Repeat("directory/", 12) + "file.txt" // 128 bytes
	if len(longPath) <= nameSize {
		t.Fatalf("fixture path is only %d bytes; it must exceed %d", len(longPath), nameSize)
	}

	encoded := writeTar(t, nil, []entry{{longPath, bundle.ModeFile, "long"}})

	r := tar.NewReader(bytes.NewReader(encoded))
	hdr, err := r.Next()
	if err != nil {
		t.Fatalf("reading PAX entry: %v", err)
	}
	if hdr.Name != longPath {
		t.Errorf("name = %q, want %q", hdr.Name, longPath)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading content: %v", err)
	}
	if string(body) != "long" {
		t.Errorf("content = %q", body)
	}
}

// A path of exactly 100 bytes fits, so it must not trigger PAX. Getting the
// boundary wrong would put an extra 512-byte header into the layer.
func TestTarNameFieldBoundary(t *testing.T) {
	t.Parallel()

	fits := strings.Repeat("a", nameSize)
	overflows := strings.Repeat("a", nameSize+1)

	if got := len(writeTar(t, nil, []entry{{fits, bundle.ModeFile, ""}})); got != blockSize+2*blockSize {
		t.Errorf("a %d-byte name produced %d bytes; expected one header plus the terminator",
			nameSize, got)
	}
	if got := len(writeTar(t, nil, []entry{{overflows, bundle.ModeFile, ""}})); got <= blockSize+2*blockSize {
		t.Errorf("a %d-byte name produced %d bytes; expected a PAX header as well",
			nameSize+1, got)
	}
}

// Content is hashed while it is written, so a source that changed between
// snapshot and packaging fails the build rather than producing a layer that
// disagrees with its own config.
func TestTarRejectsContentThatDisagreesWithTheInventory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rec     FileRecord
		content string
		code    fault.Code
	}{
		{
			"content digest differs",
			entry{"a.txt", bundle.ModeFile, "expected"}.record(),
			"actual!!",
			fault.CodeDigestMismatch,
		},
		{
			"content shorter than declared",
			entry{"a.txt", bundle.ModeFile, "expected"}.record(),
			"short",
			fault.CodeDigestMismatch,
		},
		{
			"content longer than declared",
			entry{"a.txt", bundle.ModeFile, "expected"}.record(),
			"expected and then some",
			fault.CodeDigestMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := NewTarWriter(&bytes.Buffer{})
			err := w.WriteFile(tc.rec, strings.NewReader(tc.content))
			if !stderrors.Is(err, tc.code) {
				t.Errorf("code = %q, want %q", fault.CodeOf(err), tc.code)
			}
		})
	}
}

func TestTarRejectsUnnormalizedMode(t *testing.T) {
	t.Parallel()

	rec := entry{"a.txt", 0o777, "x"}.record()
	w := NewTarWriter(&bytes.Buffer{})
	if err := w.WriteFile(rec, strings.NewReader("x")); !stderrors.Is(err, fault.CodeInternal) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeInternal)
	}
}

func TestTarRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	rec := FileRecord{Path: "big.bin", Mode: bundle.ModeFile, Size: MaxFileSize + 1}
	w := NewTarWriter(&bytes.Buffer{})
	if err := w.WriteFile(rec, strings.NewReader("")); !stderrors.Is(err, fault.CodeLimitExceeded) {
		t.Errorf("code = %q, want %q", fault.CodeOf(err), fault.CodeLimitExceeded)
	}
}

// Once the writer has failed, it must stay failed. Continuing would emit
// entries after a partial one and produce a structurally broken layer.
func TestTarWriterLatchesItsFirstError(t *testing.T) {
	t.Parallel()

	w := NewTarWriter(&bytes.Buffer{})
	first := w.WriteFile(entry{"a.txt", bundle.ModeFile, "expected"}.record(), strings.NewReader("wrong!!!"))
	if first == nil {
		t.Fatal("mismatched content was accepted")
	}

	if err := w.WriteFile(entry{"b.txt", bundle.ModeFile, "ok"}.record(), strings.NewReader("ok")); err == nil {
		t.Error("a write after a failure was accepted")
	}
	if err := w.Close(); err == nil {
		t.Error("Close after a failure reported success")
	}
}

// Exactly two zero blocks terminate the archive, and nothing follows them.
func TestTarTerminatorIsTwoZeroBlocks(t *testing.T) {
	t.Parallel()

	encoded := writeTar(t, nil, []entry{{"a.txt", bundle.ModeFile, "hi"}})

	if len(encoded)%blockSize != 0 {
		t.Errorf("stream is %d bytes, not a whole number of %d-byte blocks", len(encoded), blockSize)
	}
	tail := encoded[len(encoded)-2*blockSize:]
	for i, c := range tail {
		if c != 0 {
			t.Fatalf("terminator byte %d is %#x, want zero", i, c)
		}
	}
	// The block before the terminator is content, so it must not also be
	// zero, or the archive would have three zero blocks.
	body := encoded[len(encoded)-3*blockSize : len(encoded)-2*blockSize]
	if bytes.Equal(body, make([]byte, blockSize)) {
		t.Error("a third zero block precedes the terminator")
	}
}

// Content is padded to a block boundary with zeros.
func TestTarPadsContentWithZeros(t *testing.T) {
	t.Parallel()

	encoded := writeTar(t, nil, []entry{{"a.txt", bundle.ModeFile, "hi"}})

	padding := encoded[blockSize+2 : 2*blockSize]
	for i, c := range padding {
		if c != 0 {
			t.Fatalf("padding byte %d is %#x, want zero", i, c)
		}
	}
}

func TestTarChecksumIsValid(t *testing.T) {
	t.Parallel()

	block, err := buildHeaderBlock("a.txt", bundle.ModeFile, 2, typeRegular)
	if err != nil {
		t.Fatalf("buildHeaderBlock: %v", err)
	}

	// Recompute the way a reader does: the checksum field counts as spaces.
	var sum int64
	for i, c := range block {
		if i >= 148 && i < 156 {
			sum += ' '
			continue
		}
		sum += int64(c)
	}

	var stated int64
	for _, c := range block[148:154] {
		if c < '0' || c > '7' {
			t.Fatalf("checksum field contains non-octal byte %#x", c)
		}
		stated = stated*8 + int64(c-'0')
	}
	if stated != sum {
		t.Errorf("stated checksum %d, computed %d", stated, sum)
	}
	if block[154] != 0 {
		t.Errorf("checksum byte 6 = %#x, want NUL", block[154])
	}
	if block[155] != ' ' {
		t.Errorf("checksum byte 7 = %#x, want space", block[155])
	}
}

func TestTarHeaderMagicIsUSTAR(t *testing.T) {
	t.Parallel()

	block, err := buildHeaderBlock("a.txt", bundle.ModeFile, 0, typeRegular)
	if err != nil {
		t.Fatalf("buildHeaderBlock: %v", err)
	}
	if got := string(block[257:263]); got != "ustar\x00" {
		t.Errorf("magic = %q, want %q", got, "ustar\x00")
	}
	if got := string(block[263:265]); got != "00" {
		t.Errorf("version = %q, want %q", got, "00")
	}
	// The prefix field is never used, so it must always be zero.
	for i, c := range block[345:500] {
		if c != 0 {
			t.Fatalf("prefix byte %d is %#x; v1 never writes the prefix field", i, c)
		}
	}
}

func TestOctalFormatter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value int64
		width int
		want  string
	}{
		{0, 8, "0000000\x00"},
		{0o644, 8, "0000644\x00"},
		{0o755, 8, "0000755\x00"},
		{5, 12, "00000000005\x00"},
		{MaxFileSize, 12, "77777777777\x00"},
	}

	for _, tc := range tests {
		field := make([]byte, tc.width)
		var f octalFormatter
		f.put(field, tc.value)
		if f.err != nil {
			t.Errorf("put(%d) = %v", tc.value, f.err)
			continue
		}
		if string(field) != tc.want {
			t.Errorf("put(%d) = %q, want %q", tc.value, field, tc.want)
		}
	}
}

// A value that does not fit must be reported, never silently truncated: a
// truncated size field describes a different file.
func TestOctalFormatterRejectsOverflow(t *testing.T) {
	t.Parallel()

	var f octalFormatter
	f.put(make([]byte, 8), MaxFileSize)
	if f.err == nil {
		t.Error("a value too wide for the field was accepted")
	}

	var neg octalFormatter
	neg.put(make([]byte, 12), -1)
	if neg.err == nil {
		t.Error("a negative value was accepted")
	}
}

// The PAX record length counts its own digits, so it is self-referential.
// The boundary where the count gains a digit is where a naive implementation
// is off by one.
func TestFormatPAXRecord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key, value string
		want       string
	}{
		// "9 path=a\n" is exactly 9 bytes, counting the "9" itself.
		{"path", "a", "9 path=a\n"},
		{"size", "1", "9 size=1\n"},
		// A body of 97 plus 2 digits is 99, which still needs 2 digits.
		{"path", strings.Repeat("x", 90), "99 path=" + strings.Repeat("x", 90) + "\n"},
		// " path=" is 6 chars plus \n is 7; with a 91-char value the body is
		// 98, so the count needs 2 digits -> 100, which needs 3 -> 101.
		{"path", strings.Repeat("x", 91), "101 path=" + strings.Repeat("x", 91) + "\n"},
	}

	for _, tc := range tests {
		got := formatPAXRecord(tc.key, tc.value)
		if got != tc.want {
			t.Errorf("formatPAXRecord(%q, len %d) = %q, want %q",
				tc.key, len(tc.value), got, tc.want)
		}
		// The stated length must equal the record's actual length.
		stated, _, _ := strings.Cut(got, " ")
		if want := len(got); stated != itoa(want) {
			t.Errorf("record states length %s but is %d bytes", stated, want)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestTruncateAtRune(t *testing.T) {
	t.Parallel()

	// "設" is three bytes, so a 100-byte cut lands mid-rune.
	s := strings.Repeat("a", 98) + "設定"
	got := truncateAtRune(s, nameSize)

	if len(got) > nameSize {
		t.Errorf("result is %d bytes, want at most %d", len(got), nameSize)
	}
	if got != strings.Repeat("a", 98) {
		t.Errorf("= %q, want the prefix ending on a rune boundary", got)
	}
	if short := truncateAtRune("abc", nameSize); short != "abc" {
		t.Errorf("a short string was altered: %q", short)
	}
}

func TestGoldenTar(t *testing.T) {
	t.Parallel()

	golden.Assert(t, "testdata/format/v1/layer.tar", goldenTar(t))
}

// The compressed layer is what the OCI descriptor covers, so it gets its own
// fixture: a change in either the tar encoder or the frozen compressor
// surfaces here.
func TestGoldenLayer(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	w, err := NewGzipWriter(&buf)
	if err != nil {
		t.Fatalf("NewGzipWriter: %v", err)
	}
	if _, err := w.Write(goldenTar(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	golden.Assert(t, "testdata/format/v1/layer.tar.gz", buf.Bytes())
}

// goldenTar builds the canonical fixture tree: an empty file, binary content,
// nesting, both modes, a multibyte path, and a path long enough to need PAX.
func goldenTar(t *testing.T) []byte {
	t.Helper()

	return writeTar(t,
		[]string{"app", "app/config", "app/scripts", "café", strings.Repeat("directory/", 12)[:119]},
		[]entry{
			{"README.md", bundle.ModeFile, "hello world\n"},
			{"app/config/service.yaml", bundle.ModeFile, "a: 1\n"},
			{"app/scripts/run.sh", bundle.ModeExecutable, "#!/bin/sh\ns\n"},
			{"binary.dat", bundle.ModeFile, "\x00\x01\xfe\xff"},
			{"café/naïve.txt", bundle.ModeFile, "utf"},
			{strings.Repeat("directory/", 12) + "deep.txt", bundle.ModeFile, "deep"},
			{"empty", bundle.ModeFile, ""},
		})
}
