package shard

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jacobwoliver/xet-go/xethash"
	"github.com/jacobwoliver/xet-go/xorb"
)

func sampleShard(t testing.TB) Shard {
	t.Helper()
	parts := [][]byte{
		bytes.Repeat([]byte("a"), 10_000),
		bytes.Repeat([]byte("b"), 20_000),
		bytes.Repeat([]byte("c"), 30_000),
	}
	object, err := xorb.Encode(parts, xorb.Auto)
	if err != nil {
		t.Fatal(err)
	}
	xorbInfo, err := XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]xethash.Node, len(parts))
	hashes := make([]xethash.Hash, len(parts))
	var source []byte
	for i, part := range parts {
		hashes[i] = xethash.Chunk(part)
		nodes[i] = xethash.Node{Hash: hashes[i], Size: uint64(len(part))}
		source = append(source, part...)
	}
	sum := sha256.Sum256(source)
	return Shard{
		Files: []File{{
			Hash: xethash.File(nodes),
			Terms: []Term{{
				XorbHash: object.Hash, UnpackedBytes: uint32(len(source)), Start: 0, End: uint32(len(parts)),
				Verification: xethash.Verification(hashes),
			}},
			SHA256: &sum,
		}},
		Xorbs: []Xorb{xorbInfo},
	}
}

func TestUploadRoundTripAndLayout(t *testing.T) {
	want := sampleShard(t)
	data, err := EncodeUpload(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:32], headerMagic[:]) {
		t.Fatal("header magic differs")
	}
	if got := binary.LittleEndian.Uint64(data[32:40]); got != Version {
		t.Fatalf("version = %d", got)
	}
	if got := binary.LittleEndian.Uint64(data[40:48]); got != 0 {
		t.Fatalf("upload footer size = %d, want 0", got)
	}
	if len(data)%RecordSize != 0 {
		t.Fatalf("size %d is not record-aligned", len(data))
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || len(got.Xorbs) != 1 || got.Footer != nil {
		t.Fatalf("decoded shape = %+v", got)
	}
	if got.Files[0].Hash != want.Files[0].Hash || got.Files[0].Terms[0] != want.Files[0].Terms[0] || *got.Files[0].SHA256 != *want.Files[0].SHA256 {
		t.Fatalf("file differs: got %+v, want %+v", got.Files[0], want.Files[0])
	}
	if got.Xorbs[0].Hash != want.Xorbs[0].Hash || len(got.Xorbs[0].Chunks) != len(want.Xorbs[0].Chunks) {
		t.Fatalf("xorb differs: got %+v, want %+v", got.Xorbs[0], want.Xorbs[0])
	}
}

func TestFullAndProtectedDedupEncoding(t *testing.T) {
	value := sampleShard(t)
	full, err := EncodeFull(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(full)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Footer == nil || decoded.Footer.FileLookupEntries != 1 || decoded.Footer.XorbLookupEntries != 1 ||
		decoded.Footer.ChunkLookupEntries != uint64(len(value.Xorbs[0].Chunks)) ||
		decoded.Footer.StoredBytesOnDisk != uint64(value.Xorbs[0].SerializedBytes) ||
		decoded.Footer.StoredBytes != uint64(value.Xorbs[0].RawBytes) ||
		decoded.Footer.MaterializedBytes != uint64(value.Files[0].Terms[0].UnpackedBytes) {
		t.Fatalf("full footer = %#v", decoded.Footer)
	}

	key := xethash.Chunk([]byte("dedup protection key"))
	protected, err := EncodeProtectedDedup(value, key, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = Decode(protected)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Files) != 0 || len(decoded.Xorbs) != 1 || decoded.Footer == nil ||
		decoded.Footer.ChunkProtectionKey != key || decoded.Footer.CreatedAtUnix != 100 || decoded.Footer.KeyExpiresAtUnix != 200 {
		t.Fatalf("protected shard = %#v", decoded)
	}
	for i, chunk := range decoded.Xorbs[0].Chunks {
		if chunk.Hash != xethash.Protect(value.Xorbs[0].Chunks[i].Hash, key) {
			t.Fatalf("protected chunk %d = %s", i, chunk.Hash)
		}
	}
	if decoded.Xorbs[0].Chunks[value.Files[0].Terms[0].Start].Flags&ChunkFlagGlobalDedup == 0 {
		t.Fatal("file-start chunk was not marked globally eligible")
	}
}

func TestProtectedDedupContracts(t *testing.T) {
	value := sampleShard(t)
	if _, err := EncodeProtectedDedup(value, xethash.Zero, 1, 2); err == nil {
		t.Fatal("zero protection key succeeded")
	}
	if _, err := EncodeProtectedDedup(value, xethash.Chunk([]byte("key")), 2, 2); err == nil {
		t.Fatal("non-increasing expiry succeeded")
	}
	value.Files[0].Terms[0].XorbHash = xethash.Chunk([]byte("missing"))
	if _, err := EncodeProtectedDedup(value, xethash.Chunk([]byte("key")), 1, 2); err == nil {
		t.Fatal("missing file-start xorb succeeded")
	}
}

func TestXorbFromIngested(t *testing.T) {
	object, err := xorb.Encode([][]byte{[]byte("ingested shard metadata")}, xorb.None)
	if err != nil {
		t.Fatal(err)
	}
	ingested, err := xorb.IngestNetwork(object.Body, object.Hash)
	if err != nil {
		t.Fatal(err)
	}
	got, err := XorbFromIngested(ingested)
	if err != nil {
		t.Fatal(err)
	}
	want, err := XorbFromObject(object)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != want.Hash || got.RawBytes != want.RawBytes || got.SerializedBytes != want.SerializedBytes ||
		len(got.Chunks) != len(want.Chunks) || got.Chunks[0] != want.Chunks[0] {
		t.Fatalf("ingested xorb metadata = %#v, want %#v", got, want)
	}
	if _, err := XorbFromIngested(nil); err == nil {
		t.Fatal("nil ingested xorb succeeded")
	}
}

func TestEncodeSortsRecordsLikeRustBTreeMap(t *testing.T) {
	value := sampleShard(t)
	second := value.Files[0]
	second.Hash = xethash.Chunk([]byte("sort-second"))
	value.Files = []File{second, value.Files[0]}
	data, err := EncodeUpload(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Files[0].Hash.String() > decoded.Files[1].Hash.String() {
		t.Fatal("file records are not canonical hash order")
	}
}

func TestEncodeRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Shard)
	}{
		{"missing verification", func(s *Shard) { s.Files[0].Terms[0].Verification = xethash.Zero }},
		{"bad term size", func(s *Shard) { s.Files[0].Terms[0].UnpackedBytes++ }},
		{"bad term range", func(s *Shard) { s.Files[0].Terms[0].End++ }},
		{"bad chunk offset", func(s *Shard) { s.Xorbs[0].Chunks[1].Offset++ }},
		{"bad xorb hash", func(s *Shard) { s.Xorbs[0].Hash = xethash.Chunk([]byte("wrong")) }},
		{"xorb flags", func(s *Shard) { s.Xorbs[0].Flags = 1 }},
		{"chunk flags", func(s *Shard) { s.Xorbs[0].Chunks[0].Flags = 1 }},
		{"term flags", func(s *Shard) { s.Files[0].Terms[0].Flags = 1 }},
		{"duplicate xorb", func(s *Shard) { s.Xorbs = append(s.Xorbs, s.Xorbs[0]) }},
		{"duplicate file", func(s *Shard) { s.Files = append(s.Files, s.Files[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := sampleShard(t)
			test.mutate(&value)
			if _, err := EncodeUpload(value); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}

func TestValidateRegistrationRecomputesFilesAndDedupKeys(t *testing.T) {
	value := sampleShard(t)
	stored := value.Xorbs[0]
	lookup := func(hash xethash.Hash) (Xorb, bool, error) {
		return stored, hash == stored.Hash, nil
	}
	registration, err := ValidateRegistration(value, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(registration.Files) != 1 || registration.Files[0].Size != uint64(stored.RawBytes) ||
		len(registration.Xorbs) != 1 || len(registration.GlobalDedupChunks) == 0 {
		t.Fatalf("registration = %#v", registration)
	}
	first := stored.Chunks[value.Files[0].Terms[0].Start].Hash
	if !containsHash(registration.GlobalDedupChunks, first) {
		t.Fatalf("file-start chunk %s is not globally eligible", first)
	}

	external := value
	external.Xorbs = nil
	registration, err = ValidateRegistration(external, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(registration.Files) != 1 || len(registration.Xorbs) != 0 || len(registration.GlobalDedupChunks) != 0 {
		t.Fatalf("external registration = %#v", registration)
	}
}

func TestValidateRegistrationRejectsStorageAndIdentityConflicts(t *testing.T) {
	value := sampleShard(t)
	stored := value.Xorbs[0]
	if _, err := ValidateRegistration(value, nil); err == nil {
		t.Fatal("nil lookup succeeded")
	}
	if _, err := ValidateRegistration(value, func(xethash.Hash) (Xorb, bool, error) {
		return Xorb{}, false, nil
	}); err == nil {
		t.Fatal("missing xorb succeeded")
	}
	wantErr := errors.New("lookup failed")
	if _, err := ValidateRegistration(value, func(xethash.Hash) (Xorb, bool, error) {
		return Xorb{}, false, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("lookup error = %v", err)
	}
	conflict := stored
	conflict.Chunks = append([]XorbChunk(nil), stored.Chunks...)
	conflict.Chunks[0].Hash = xethash.Chunk([]byte("different chunk"))
	if _, err := ValidateRegistration(value, func(xethash.Hash) (Xorb, bool, error) {
		return conflict, true, nil
	}); err == nil {
		t.Fatal("conflicting xorb metadata succeeded")
	}
	value.Files[0].Hash = xethash.Chunk([]byte("wrong file identity"))
	if _, err := ValidateRegistration(value, func(hash xethash.Hash) (Xorb, bool, error) {
		return stored, hash == stored.Hash, nil
	}); err == nil {
		t.Fatal("wrong file identity succeeded")
	}
}

func containsHash(values []xethash.Hash, want xethash.Hash) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestMetadataValidationContracts(t *testing.T) {
	if _, err := XorbFromObject(nil); err == nil {
		t.Fatal("nil xorb object succeeded")
	}
	formatErr := &FormatError{Offset: 7, Reason: "reason"}
	if got := formatErr.Error(); got != "shard: malformed data at offset 7: reason" {
		t.Fatalf("FormatError = %q", got)
	}
	if err := validate(nil, true); err == nil {
		t.Fatal("nil shard validated")
	}

	tests := []struct {
		name   string
		mutate func(*Shard)
	}{
		{"upload footer", func(s *Shard) { s.Footer = &Footer{} }},
		{"xorb no chunks", func(s *Shard) { s.Xorbs[0].Chunks = nil }},
		{"xorb raw size", func(s *Shard) { s.Xorbs[0].RawBytes++ }},
		{"xorb raw overflow", func(s *Shard) {
			s.Xorbs[0].Chunks = []XorbChunk{{Length: ^uint32(0)}, {Offset: ^uint32(0), Length: 1}}
		}},
		{"file flags", func(s *Shard) { s.Files[0].Flags = 1 }},
		{"empty term", func(s *Shard) { s.Files[0].Terms[0].End = s.Files[0].Terms[0].Start }},
		{"zero term bytes", func(s *Shard) { s.Files[0].Terms[0].UnpackedBytes = 0 }},
		{"verification mismatch", func(s *Shard) { s.Files[0].Terms[0].Verification = xethash.Chunk([]byte("wrong")) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := sampleShard(t)
			test.mutate(&value)
			if err := validate(&value, true); err == nil {
				t.Fatal("invalid metadata validated")
			}
		})
	}
	if _, ok := checkedTableEnd(^uint64(0)-1, 2, 2); ok {
		t.Fatal("overflowing table bounds succeeded")
	}
	if end, ok := checkedTableEnd(3, 2, 4); !ok || end != 11 {
		t.Fatalf("checkedTableEnd = %d, %v", end, ok)
	}
	if allZero([]byte{0, 1}) || !allZero(nil) || isBookend(nil) {
		t.Fatal("record helper classification differs")
	}
	if _, err := takeRecord(make([]byte, RecordSize), -1, RecordSize); err == nil {
		t.Fatal("negative record offset succeeded")
	}
}

func TestDecodeRejectsSemanticCorruption(t *testing.T) {
	base, err := EncodeUpload(sampleShard(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]byte){
		"magic":                 func(data []byte) { data[0] ^= 1 },
		"version":               func(data []byte) { binary.LittleEndian.PutUint64(data[32:40], Version+1) },
		"footer size":           func(data []byte) { binary.LittleEndian.PutUint64(data[40:48], 1) },
		"file flags":            func(data []byte) { binary.LittleEndian.PutUint32(data[80:84], 1) },
		"file reserved":         func(data []byte) { data[88] = 1 },
		"file count":            func(data []byte) { binary.LittleEndian.PutUint32(data[84:88], ^uint32(0)) },
		"verification reserved": func(data []byte) { data[176] = 1 },
		"SHA reserved":          func(data []byte) { data[224] = 1 },
		"xorb count":            func(data []byte) { binary.LittleEndian.PutUint32(data[324:328], ^uint32(0)) },
		"chunk reserved":        func(data []byte) { data[380] = 1 },
		"trailing data":         func(data []byte) { data[len(data)-1] = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			if name == "trailing data" {
				data = append(data, 0)
			} else {
				mutate(data)
			}
			if _, err := Decode(data); err == nil {
				t.Fatal("semantic corruption decoded")
			}
		})
	}
}

func TestUploadAcceptsOfficialZeroSerializedSize(t *testing.T) {
	value := sampleShard(t)
	data, err := EncodeUpload(value)
	if err != nil {
		t.Fatal(err)
	}
	// One file header, term, verification, SHA-256 extension, and bookend
	// precede the xorb header in this fixture.
	xorbHeader := HeaderSize + 5*RecordSize
	binary.LittleEndian.PutUint32(data[xorbHeader+44:xorbHeader+48], 0)
	decoded, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Xorbs[0].SerializedBytes != 0 {
		t.Fatalf("legacy serialized size = %d", decoded.Xorbs[0].SerializedBytes)
	}
	encoded, err := EncodeUpload(*decoded)
	if err != nil {
		t.Fatalf("official zero serialized size rejected for upload: %v", err)
	}
	if roundTrip, err := Decode(encoded); err != nil || roundTrip.Xorbs[0].SerializedBytes != 0 {
		t.Fatalf("zero serialized size round trip = %#v, %v", roundTrip, err)
	}
}

func TestDecodeRejectsEveryTruncation(t *testing.T) {
	data, err := EncodeUpload(sampleShard(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range data {
		_, err := Decode(data[:i])
		if err == nil {
			t.Fatalf("accepted truncation at %d of %d", i, len(data))
		}
		var formatErr *FormatError
		if !errors.As(err, &formatErr) {
			t.Fatalf("truncation %d error type = %T", i, err)
		}
	}
}

func TestFooterValidation(t *testing.T) {
	upload, err := EncodeUpload(sampleShard(t))
	if err != nil {
		t.Fatal(err)
	}
	full := append([]byte(nil), upload...)
	binary.LittleEndian.PutUint64(full[40:48], FooterSize)
	footerStart := uint64(len(full))
	footer := make([]byte, FooterSize)
	values := []uint64{
		1, HeaderSize,
		uint64(HeaderSize + RecordSize*(1+2*len(sampleShard(t).Files[0].Terms)+1) + RecordSize),
		footerStart, 0,
		footerStart, 0,
		footerStart, 0,
	}
	for i, value := range values {
		binary.LittleEndian.PutUint64(footer[i*8:(i+1)*8], value)
	}
	binary.LittleEndian.PutUint64(footer[192:200], footerStart)
	full = append(full, footer...)
	decoded, err := Decode(full)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Footer == nil || decoded.Footer.Offset != footerStart {
		t.Fatalf("footer = %+v", decoded.Footer)
	}
	full[len(full)-1] ^= 1
	if _, err := Decode(full); err == nil {
		t.Fatal("accepted corrupt footer offset")
	}
}

func FuzzDecode(f *testing.F) {
	data, err := EncodeUpload(sampleShard(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			return
		}
		_, _ = Decode(data)
	})
}

func BenchmarkEncodeUpload(b *testing.B) {
	value := sampleShard(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := EncodeUpload(value); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeUpload(b *testing.B) {
	data, err := EncodeUpload(sampleShard(b))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}
