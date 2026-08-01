package chunker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"slices"
	"strconv"
	"testing"
)

func testData(n int) []byte {
	r := rand.New(rand.NewSource(42))
	b := make([]byte, n)
	_, _ = r.Read(b)
	return b
}

func boundaries(t *testing.T, r io.Reader, cfg Config) ([]int, []byte) {
	t.Helper()
	ends := make([]int, 0)
	joined := make([]byte, 0)
	err := SplitContext(context.Background(), r, cfg, func(c Chunk) error {
		if c.Offset != int64(len(joined)) {
			t.Fatalf("chunk offset = %d, want %d", c.Offset, len(joined))
		}
		joined = append(joined, c.Data...)
		ends = append(ends, len(joined))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ends, joined
}

type maxReader struct {
	r   io.Reader
	max int
}

func (r maxReader) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	return r.r.Read(p)
}

func TestReaderSegmentationDoesNotChangeBoundaries(t *testing.T) {
	data := testData(4 << 20)
	want, joined := boundaries(t, bytes.NewReader(data), DefaultConfig)
	if !bytes.Equal(joined, data) {
		t.Fatal("chunks did not reproduce input")
	}
	for _, size := range []int{1, 7, 63, 64, 65, 8191, 8192, 65536, 131073} {
		got, gotData := boundaries(t, maxReader{bytes.NewReader(data), size}, DefaultConfig)
		if !slices.Equal(got, want) {
			t.Errorf("reader size %d boundaries differ\ngot  %v\nwant %v", size, got, want)
		}
		if !bytes.Equal(gotData, data) {
			t.Errorf("reader size %d data differs", size)
		}
	}
}

func TestIncrementalWriterMatchesSplit(t *testing.T) {
	data := testData(2<<20 + 17)
	wantEnds, _ := boundaries(t, bytes.NewReader(data), DefaultConfig)
	for _, stride := range []int{1, 7, 8191, 8192, 65537, len(data)} {
		var gotEnds []int
		var joined []byte
		writer, err := NewWriter(context.Background(), DefaultConfig, func(chunk Chunk) error {
			joined = append(joined, chunk.Data...)
			gotEnds = append(gotEnds, len(joined))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for start := 0; start < len(data); start += stride {
			end := min(start+stride, len(data))
			if _, err := writer.Write(data[start:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(gotEnds, wantEnds) || !bytes.Equal(joined, data) {
			t.Fatalf("stride %d produced different chunks", stride)
		}
	}
}

func TestChunkLimitsAndEmptyInput(t *testing.T) {
	for _, n := range []int{0, 1, MinSize - 1, MinSize, MinSize + 1, MaxSize - 1, MaxSize, MaxSize + 1} {
		chunks := Bytes(make([]byte, n))
		if n == 0 && len(chunks) != 0 {
			t.Fatalf("Bytes(empty) returned %d chunks", len(chunks))
		}
		var total int
		for i, c := range chunks {
			total += len(c.Data)
			if len(c.Data) > MaxSize {
				t.Errorf("length %d chunk %d exceeds maximum: %d", n, i, len(c.Data))
			}
			if i+1 < len(chunks) && len(c.Data) < MinSize {
				t.Errorf("length %d non-final chunk %d below minimum: %d", n, i, len(c.Data))
			}
		}
		if total != n {
			t.Errorf("length %d reconstructed as %d", n, total)
		}
	}
}

func TestSplitCancellationAndEmitterError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SplitContext(ctx, bytes.NewReader([]byte("x")), DefaultConfig, func(Chunk) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	want := errors.New("stop")
	if err := Split(bytes.NewReader([]byte("x")), func(Chunk) error { return want }); !errors.Is(err, want) {
		t.Fatalf("emitter error = %v", err)
	}
}

func TestStableBoundary(t *testing.T) {
	boundaries := []int{0, 10_000, 30_000, 50_000, 180_000}
	got, ok := NextStableBoundary(0, boundaries)
	if !ok || got != 50_000 {
		t.Fatalf("NextStableBoundary = %d, %v; want 50000, true", got, ok)
	}
	if _, ok := NextStableBoundary(50_001, boundaries); ok {
		t.Fatal("unexpected stable boundary")
	}
}

func TestInputAndConfigurationContracts(t *testing.T) {
	emit := func(Chunk) error { return nil }
	if err := SplitContext(context.Background(), nil, DefaultConfig, emit); err == nil {
		t.Fatal("nil reader succeeded")
	}
	if err := SplitContext(context.Background(), bytes.NewReader(nil), DefaultConfig, nil); err == nil {
		t.Fatal("nil emitter succeeded")
	}
	if _, err := NewWriter(nil, DefaultConfig, emit); err == nil { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatal("nil context succeeded")
	}
	if _, err := NewWriter(context.Background(), DefaultConfig, nil); err == nil {
		t.Fatal("nil emitter succeeded")
	}

	for name, cfg := range map[string]Config{
		"small target":         {TargetSize: 64},
		"non-power target":     {TargetSize: 100},
		"maximum overflow":     {TargetSize: 1 << (strconv.IntSize - 2)},
		"negative minimum":     {TargetSize: 128, MinSize: -1, MaxSize: 256},
		"reversed range":       {TargetSize: 128, MinSize: 5, MaxSize: 5},
		"negative read buffer": {TargetSize: 128, ReadBufferSize: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewWriter(context.Background(), cfg, emit); err == nil {
				t.Fatalf("NewWriter(%#v) succeeded", cfg)
			}
			if err := SplitContext(context.Background(), bytes.NewReader(nil), cfg, emit); err == nil {
				t.Fatalf("SplitContext(%#v) succeeded", cfg)
			}
		})
	}
}

type countReader struct {
	count int
	err   error
}

func (r countReader) Read([]byte) (int, error) { return r.count, r.err }

type dataErrorReader struct {
	done bool
}

func (r *dataErrorReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	p[0] = 'x'
	return 1, errors.New("reader failed")
}

func TestReaderAndWriterFailureContracts(t *testing.T) {
	emit := func(Chunk) error { return nil }
	for name, reader := range map[string]io.Reader{
		"negative count": countReader{count: -1},
		"large count":    countReader{count: 2},
		"no progress":    countReader{},
	} {
		t.Run(name, func(t *testing.T) {
			err := SplitContext(context.Background(), reader, Config{TargetSize: 128, ReadBufferSize: 1}, emit)
			if err == nil {
				t.Fatal("invalid reader succeeded")
			}
			if name == "no progress" && !errors.Is(err, io.ErrNoProgress) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	wantReadErr := errors.New("reader failed")
	reader := &dataErrorReader{}
	if err := SplitContext(context.Background(), reader, Config{TargetSize: 128, ReadBufferSize: 1}, emit); err == nil || err.Error() != wantReadErr.Error() {
		t.Fatalf("reader error = %v", err)
	}

	wantEmitErr := errors.New("emitter failed")
	writer, err := NewWriter(context.Background(), Config{TargetSize: 128, MinSize: 1, MaxSize: 2}, func(Chunk) error { return wantEmitErr })
	if err != nil {
		t.Fatal(err)
	}
	if n, err := writer.Write([]byte("ab")); n != 2 || !errors.Is(err, wantEmitErr) {
		t.Fatalf("first Write = %d, %v", n, err)
	}
	if n, err := writer.Write([]byte("c")); n != 0 || !errors.Is(err, wantEmitErr) {
		t.Fatalf("second Write = %d, %v", n, err)
	}
	if err := writer.Close(); !errors.Is(err, wantEmitErr) {
		t.Fatalf("Close = %v", err)
	}
	if err := writer.Close(); err == nil {
		t.Fatal("second Close succeeded")
	}
	if n, err := writer.Write(nil); n != 0 || err == nil {
		t.Fatalf("Write after Close = %d, %v", n, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	canceled, err := NewWriter(ctx, DefaultConfig, emit)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if n, err := canceled.Write([]byte("x")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Write = %d, %v", n, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	canceled, err = NewWriter(ctx, DefaultConfig, emit)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := canceled.Close(); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Close = %v", err)
	}

	chunk := Chunk{Offset: 7, Data: []byte("abc")}
	if chunk.End() != 10 {
		t.Fatalf("Chunk.End = %d", chunk.End())
	}
}

func FuzzReaderSegmentation(f *testing.F) {
	f.Add([]byte(""), uint16(1))
	f.Add(testData(MaxSize+1), uint16(8192))
	f.Fuzz(func(t *testing.T, data []byte, readSize uint16) {
		if len(data) > 2<<20 {
			return
		}
		want, joined := boundaries(t, bytes.NewReader(data), DefaultConfig)
		size := int(readSize) + 1
		got, segmented := boundaries(t, maxReader{bytes.NewReader(data), size}, DefaultConfig)
		if !slices.Equal(got, want) || !bytes.Equal(segmented, joined) || !bytes.Equal(joined, data) {
			t.Fatalf("segmentation changed chunking for read size %d", size)
		}
	})
}

func BenchmarkSplit64MiB(b *testing.B) {
	data := testData(64 << 20)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := Split(bytes.NewReader(data), func(Chunk) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}
