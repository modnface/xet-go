package xethash

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/jmwoliver/blake3"
)

func TestHashCanonicalText(t *testing.T) {
	var raw Hash
	for i := range raw {
		raw[i] = byte(i)
	}
	const want = "07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918"
	if got := raw.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	got, err := Parse(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != raw {
		t.Fatalf("Parse(String()) = %x, want %x", got, raw)
	}
}

func TestHashOfficialEndianVector(t *testing.T) {
	raw := []byte{
		22, 175, 58, 132, 4, 75, 131, 214, 190, 153, 138, 66, 226, 3, 153, 242,
		204, 86, 80, 234, 249, 153, 80, 99, 159, 80, 65, 138, 236, 231, 149, 78,
	}
	h, err := FromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	const want = "d6834b04843aaf16f29903e2428a99be635099f9ea5056cc4e95e7ec8a41509f"
	if h.String() != want {
		t.Fatalf("String() = %q, want %q", h, want)
	}
}

func TestHashTextAndJSONRoundTrip(t *testing.T) {
	h := Chunk([]byte("Xet protocol"))
	text, err := h.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var fromText Hash
	if err := fromText.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if fromText != h {
		t.Fatalf("text round trip = %v, want %v", fromText, h)
	}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Hash
	if err := json.Unmarshal(data, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON != h {
		t.Fatalf("JSON round trip = %v, want %v", fromJSON, h)
	}
	if got, err := ParseBase64(h.Base64()); err != nil || got != h {
		t.Fatalf("base64 round trip = %v, %v", got, err)
	}
}

func TestHashRejectsMalformedValues(t *testing.T) {
	for _, input := range []string{"", "abc", string(make([]byte, 64)), "g000000000000000000000000000000000000000000000000000000000000000"} {
		_, err := Parse(input)
		if !errors.Is(err, ErrInvalidHash) {
			t.Errorf("Parse(%q) error = %v, want ErrInvalidHash", input, err)
		}
	}
	if _, err := FromBytes(make([]byte, 31)); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("FromBytes error = %v, want ErrInvalidHash", err)
	}
}

func TestHashConvenienceAndFailureContracts(t *testing.T) {
	hash := Chunk([]byte("copies"))
	bytesValue := hash.Bytes()
	if len(bytesValue) != Size {
		t.Fatalf("Bytes length = %d", len(bytesValue))
	}
	bytesValue[0] ^= 0xff
	if hash.Bytes()[0] == bytesValue[0] {
		t.Fatal("Bytes aliases the hash")
	}
	if hash.IsZero() || !Zero.IsZero() {
		t.Fatal("IsZero classification differs")
	}
	if _, err := ParseBase64("!"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("ParseBase64 error = %v", err)
	}
	if _, err := ParseBase64("AA"); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("short ParseBase64 error = %v", err)
	}
	var decoded Hash
	if err := decoded.UnmarshalText([]byte("bad")); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("UnmarshalText error = %v", err)
	}
	if err := decoded.UnmarshalJSON([]byte("123")); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("UnmarshalJSON error = %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustParse did not panic")
		}
	}()
	_ = MustParse("bad")
}

func TestOfficialMerkleVectors(t *testing.T) {
	h1 := MustParse("cfc5d07f6f03c29bbf424132963fe08d19a37d5757aaf520bf08119f05cd56d6")
	h2 := MustParse("c3e67584b5c4fc2a89837ec39e40f2c8a6bb0b2987ac94cd4b31e5fbdd210a72")
	h3 := MustParse("0d2beb91b9196929a5ddec9f6e306924ddf4a24268e3e59fd8464738d525af37")
	tests := []struct {
		name  string
		nodes []Node
		xorb  string
		file  string
	}{
		{"empty", nil, Zero.String(), Zero.String()},
		{"single", []Node{{h1, 100}}, h1.String(), "8e16257caa3fe079d484d872a8975264b2ff683b0d6db9028cc7c0f968a45661"},
		{"three", []Node{{h1, 100}, {h2, 200}, {h3, 300}}, "71ec1275fca074724e2dd666921b3277c7cee603e4d025bcab2d4050015be2bc", "54e55dccc6653c612bdb5576c5d3cb34bb31bc4e100248abccf4c908b3ef7715"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Xorb(tt.nodes).String(); got != tt.xorb {
				t.Errorf("Xorb() = %s, want %s", got, tt.xorb)
			}
			if got := File(tt.nodes).String(); got != tt.file {
				t.Errorf("File() = %s, want %s", got, tt.file)
			}
		})
	}
}

func TestVerificationOrderMatters(t *testing.T) {
	a := Chunk([]byte("a"))
	b := Chunk([]byte("b"))
	if Verification([]Hash{a, b}) == Verification([]Hash{b, a}) {
		t.Fatal("verification hash ignored chunk order")
	}
}

func TestChunkMatchesStreamingBLAKE3AtTreeBoundaries(t *testing.T) {
	for _, size := range []int{
		0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048,
		8191, 8192, 65535, 65536, 131071, 131072, 131073,
	} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*131 + i>>8)
		}
		hasher := blake3.New(Size, dataKey[:])
		_, _ = hasher.Write(data)
		var want Hash
		copy(want[:], hasher.Sum(nil))
		if got := Chunk(data); got != want {
			t.Fatalf("size %d: Chunk = %s, streaming BLAKE3 = %s", size, got, want)
		}
	}
}

func TestChunksMatchesIndividualHashes(t *testing.T) {
	sizes := []int{0, 1, 64, 1024, 1025, 8192, 32768, 65536, 131072}
	inputs := make([][]byte, len(sizes))
	for i, size := range sizes {
		inputs[i] = make([]byte, size)
		for j := range inputs[i] {
			inputs[i][j] = byte(i*17 + j*131 + j>>8)
		}
	}
	got := Chunks(inputs)
	if len(got) != len(inputs) {
		t.Fatalf("Chunks returned %d hashes, want %d", len(got), len(inputs))
	}
	for i := range inputs {
		if want := Chunk(inputs[i]); got[i] != want {
			t.Fatalf("chunk %d (size %d): Chunks = %s, Chunk = %s", i, len(inputs[i]), got[i], want)
		}
	}
	if got := Chunks(nil); got == nil || len(got) != 0 {
		t.Fatalf("Chunks(nil) = %#v, want non-nil empty slice", got)
	}
}

func TestChunksConcurrent(t *testing.T) {
	inputs := make([][]byte, 32)
	for i := range inputs {
		inputs[i] = make([]byte, 64<<10)
		inputs[i][0] = byte(i)
	}
	want := Chunks(inputs)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got := Chunks(inputs)
			if !slices.Equal(got, want) {
				t.Errorf("concurrent Chunks result differs")
			}
		}()
	}
	wait.Wait()
}

func TestChunksSmallBatchFallback(t *testing.T) {
	inputs := [][]byte{make([]byte, 8<<10), make([]byte, 8<<10)}
	got := Chunks(inputs)
	for i := range inputs {
		if want := Chunk(inputs[i]); got[i] != want {
			t.Fatalf("small chunk %d: Chunks = %s, Chunk = %s", i, got[i], want)
		}
	}
}

func TestChunkBatchWorkerBudgetAndSerialHasher(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previousProcs)

	chunkBatchBudget.Lock()
	previousActive := chunkBatchBudget.active
	chunkBatchBudget.active = 0
	chunkBatchBudget.Unlock()
	defer func() {
		chunkBatchBudget.Lock()
		chunkBatchBudget.active = previousActive
		chunkBatchBudget.Unlock()
	}()

	workers := claimChunkBatchWorkers(4)
	if workers != 4 {
		t.Fatalf("first worker claim = %d, want 4", workers)
	}
	contended := claimChunkBatchWorkers(4)
	if contended != 1 {
		t.Fatalf("contended worker claim = %d, want 1", contended)
	}
	releaseChunkBatchWorkers(contended)
	releaseChunkBatchWorkers(workers)

	data := make([]byte, 64<<10)
	if got, want := pooledBatchHash(data), Chunk(data); got != want {
		t.Fatalf("serial batch hash = %s, want %s", got, want)
	}
}

func TestInternalLargeInput(t *testing.T) {
	data := make([]byte, 8<<10)
	got := Internal(data)
	h := blake3.New(Size, internalKey[:])
	_, _ = h.Write(data)
	var want Hash
	copy(want[:], h.Sum(nil))
	if got != want {
		t.Fatalf("Internal = %s, streaming BLAKE3 = %s", got, want)
	}
}

func FuzzHashTextRoundTrip(f *testing.F) {
	f.Add(make([]byte, Size))
	f.Add([]byte("01234567890123456789012345678901"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) != Size {
			return
		}
		h, err := FromBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(h.String())
		if err != nil {
			t.Fatal(err)
		}
		if got != h {
			t.Fatalf("round trip = %x, want %x", got, h)
		}
	})
}

func BenchmarkChunkHash64KiB(b *testing.B) {
	data := make([]byte, 64<<10)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Chunk(data)
	}
}

func BenchmarkChunkHashBatch64KiB(b *testing.B) {
	chunks := make([][]byte, 1024)
	for i := range chunks {
		chunks[i] = make([]byte, 64<<10)
	}
	b.SetBytes(int64(len(chunks) * len(chunks[0])))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Chunks(chunks)
	}
}

func BenchmarkChunksCrossover(b *testing.B) {
	for _, test := range []struct {
		name  string
		count int
		size  int
	}{
		{"2x32KiB", 2, 32 << 10},
		{"4x16KiB", 4, 16 << 10},
		{"8x8KiB", 8, 8 << 10},
		{"2x64KiB", 2, 64 << 10},
		{"4x32KiB", 4, 32 << 10},
		{"16x8KiB", 16, 8 << 10},
		{"2x128KiB", 2, 128 << 10},
		{"4x64KiB", 4, 64 << 10},
		{"8x32KiB", 8, 32 << 10},
		{"32x8KiB", 32, 8 << 10},
	} {
		chunks := make([][]byte, test.count)
		for i := range chunks {
			chunks[i] = make([]byte, test.size)
		}
		b.Run(test.name+"/individual", func(b *testing.B) {
			b.SetBytes(int64(test.count * test.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				hashes := make([]Hash, len(chunks))
				for i := range chunks {
					hashes[i] = Chunk(chunks[i])
				}
			}
		})
		b.Run(test.name+"/batch", func(b *testing.B) {
			b.SetBytes(int64(test.count * test.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = Chunks(chunks)
			}
		})
	}
}

func BenchmarkMerkle1024Chunks(b *testing.B) {
	nodes := make([]Node, 1024)
	for i := range nodes {
		nodes[i] = Node{Hash: Chunk([]byte{byte(i), byte(i >> 8)}), Size: 64 << 10}
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = File(nodes)
	}
}

func BenchmarkSmallKeyedHashes(b *testing.B) {
	for _, size := range []int{32, 64, 256, 792, 1024} {
		data := make([]byte, size)
		b.Run(fmt.Sprintf("chunk-%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = Chunk(data)
			}
		})
		b.Run(fmt.Sprintf("internal-%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = Internal(data)
			}
		})
	}
	b.Run("protect", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = Protect(Hash{1}, Hash{2})
		}
	})
}

func BenchmarkVerificationHashes(b *testing.B) {
	for _, count := range []int{1, 16, 1024} {
		hashes := make([]Hash, count)
		b.Run(fmt.Sprintf("hashes-%d", count), func(b *testing.B) {
			b.SetBytes(int64(count * Size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = Verification(hashes)
			}
		})
	}
}
