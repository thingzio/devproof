package devproof_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thingzio/devproof"
)

// Benchmarks exist to turn the default resource limits from guesses into
// measurements (DP-020), and to catch the two regressions that matter: an
// operation whose time stops being linear in payload size, and one whose
// memory stops being independent of it.
//
// Time is reported per operation as usual. Bytes per operation is the number
// to watch: expansion streams, so its allocation should not track the payload.

// benchTree writes a source tree of count files of the given size.
func benchTree(b *testing.B, count int, size int) string {
	b.Helper()

	dir := b.TempDir()
	// Pseudo-random rather than repeated filler. Highly compressible content
	// trips the expansion-ratio guard, and it would also report a throughput
	// that no real payload achieves.
	random := rand.NewChaCha8([32]byte{})
	content := make([]byte, size)
	for i := range count {
		random.Read(content)
		// Spread files across directories: a flat tree of ten thousand files
		// is not what the path handling actually sees in practice.
		sub := filepath.Join(dir, fmt.Sprintf("d%02d", i%64))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			b.Fatalf("creating %s: %v", sub, err)
		}
		name := filepath.Join(sub, fmt.Sprintf("f%06d.bin", i))
		if err := os.WriteFile(name, content, 0o644); err != nil {
			b.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}

func benchClient(b *testing.B) *devproof.Client {
	b.Helper()

	client, err := devproof.New()
	if err != nil {
		b.Fatalf("creating a client: %v", err)
	}
	b.Cleanup(func() { _ = client.Close() })
	return client
}

// The shapes below bracket what the defaults are meant to cover: many small
// files, which is configuration, and fewer large ones, which is assets.
var shapes = []struct {
	name  string
	count int
	size  int
}{
	{"100x4KiB", 100, 4 << 10},
	{"1000x4KiB", 1000, 4 << 10},
	{"100x256KiB", 100, 256 << 10},
	{"10x8MiB", 10, 8 << 20},
}

func BenchmarkBuild(b *testing.B) {
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			source := benchTree(b, shape.count, shape.size)
			ctx := context.Background()
			client := benchClient(b)

			b.SetBytes(int64(shape.count * shape.size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; b.Loop(); i++ {
				dest := filepath.Join(b.TempDir(), fmt.Sprintf("layout%d", i))
				if _, err := client.Build(ctx, devproof.BuildRequest{
					SourcePath:  source,
					Destination: "oci-layout://" + dest,
				}); err != nil {
					b.Fatalf("build: %v", err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			ctx := context.Background()
			client := benchClient(b)

			built, err := client.Build(ctx, devproof.BuildRequest{
				SourcePath:  benchTree(b, shape.count, shape.size),
				Destination: "oci-layout://" + filepath.Join(b.TempDir(), "layout"),
			})
			if err != nil {
				b.Fatalf("build: %v", err)
			}

			b.SetBytes(int64(shape.count * shape.size))
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				if _, err := client.Verify(ctx, devproof.VerifyRequest{
					Reference: built.Reference,
				}); err != nil {
					b.Fatalf("verify: %v", err)
				}
			}
		})
	}
}

// Expansion streams the layer rather than buffering it, so allocated bytes
// per operation should stay roughly flat as the payload grows. A regression
// here means a whole bundle is being held in memory, which is what the
// default limits would otherwise have to defend against.
func BenchmarkExpand(b *testing.B) {
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			ctx := context.Background()
			client := benchClient(b)

			built, err := client.Build(ctx, devproof.BuildRequest{
				SourcePath:  benchTree(b, shape.count, shape.size),
				Destination: "oci-layout://" + filepath.Join(b.TempDir(), "layout"),
			})
			if err != nil {
				b.Fatalf("build: %v", err)
			}

			b.SetBytes(int64(shape.count * shape.size))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; b.Loop(); i++ {
				dest := filepath.Join(b.TempDir(), fmt.Sprintf("out%d", i))
				if _, err := client.Expand(ctx, devproof.ExpandRequest{
					Reference:   built.Reference,
					Destination: dest,
				}); err != nil {
					b.Fatalf("expand: %v", err)
				}
			}
		})
	}
}

// BenchmarkPeakMemory records the high-water mark rather than the total, which
// is the number that decides whether a default limit is survivable on a small
// CI runner.
func BenchmarkPeakMemory(b *testing.B) {
	for _, shape := range shapes {
		b.Run(shape.name, func(b *testing.B) {
			ctx := context.Background()
			client := benchClient(b)
			source := benchTree(b, shape.count, shape.size)

			b.ReportAllocs()
			b.ResetTimer()

			var peak uint64
			for i := 0; b.Loop(); i++ {
				dest := filepath.Join(b.TempDir(), fmt.Sprintf("layout%d", i))
				built, err := client.Build(ctx, devproof.BuildRequest{
					SourcePath:  source,
					Destination: "oci-layout://" + dest,
				})
				if err != nil {
					b.Fatalf("build: %v", err)
				}
				if _, err := client.Expand(ctx, devproof.ExpandRequest{
					Reference:   built.Reference,
					Destination: filepath.Join(b.TempDir(), fmt.Sprintf("out%d", i)),
				}); err != nil {
					b.Fatalf("expand: %v", err)
				}

				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				peak = max(peak, stats.HeapAlloc)
			}
			b.ReportMetric(float64(peak)/(1<<20), "peakHeapMiB")
		})
	}
}

// Memory must not scale with payload size.
//
// This is a correctness property, not a performance nicety: the documented
// default limits allow an 8 GiB expansion, and a build whose memory tracked
// payload size would make that limit bounded by the caller's RAM rather than
// by what they configured. Both the layer staging and the layout writer
// stream, and a regression in either would show up here as growth.
func TestBuildMemoryDoesNotScaleWithPayload(t *testing.T) {
	measure := func(count, size int) float64 {
		source := t.TempDir()
		random := rand.NewChaCha8([32]byte{})
		content := make([]byte, size)
		for i := range count {
			random.Read(content)
			name := filepath.Join(source, fmt.Sprintf("f%04d.bin", i))
			if err := os.WriteFile(name, content, 0o644); err != nil {
				t.Fatalf("writing %s: %v", name, err)
			}
		}

		client, err := devproof.New()
		if err != nil {
			t.Fatalf("creating a client: %v", err)
		}
		defer func() { _ = client.Close() }()

		// Bytes allocated, not allocation count. Buffering a payload changes
		// how much is allocated, barely changing how many times, so a count
		// would not see the regression this test exists to catch.
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		if _, err := client.Build(context.Background(), devproof.BuildRequest{
			SourcePath:  source,
			Destination: "oci-layout://" + filepath.Join(t.TempDir(), "layout"),
		}); err != nil {
			t.Fatalf("build: %v", err)
		}

		runtime.ReadMemStats(&after)
		return float64(after.TotalAlloc - before.TotalAlloc)
	}

	// Same file count, sixty-four times the bytes.
	const (
		smallPayload = 8 * (64 << 10) // 512 KiB
		largePayload = 8 * (4 << 20)  // 32 MiB
	)
	small := measure(8, 64<<10)
	large := measure(8, 4<<20)

	// The payload grows by 32 MiB; allocation is allowed to grow by a small
	// fraction of that. A buffering implementation allocates several times
	// the payload here, so the bar does not need to be tight to catch it.
	if growth := large - small; growth > largePayload/4 {
		t.Errorf("build allocation scales with payload size: "+
			"%.1f MiB for a 512KiB payload, %.1f MiB for a 32MiB payload (growth %.1f MiB)",
			small/(1<<20), large/(1<<20), growth/(1<<20))
	}
}
