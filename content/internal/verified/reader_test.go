package verified

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jmwoliver/xet-go/content"
)

func TestReaderVerification(t *testing.T) {
	body := []byte("verified ordinary content")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	reader := New(context.Background(), io.NopCloser(bytes.NewReader(body)), blob, blob.Size, true)
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("verified read = %q, %v", got, err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}

	wrong := blob
	wrong.SHA256[0] ^= 0xff
	reader = New(context.Background(), io.NopCloser(bytes.NewReader(body)), wrong, wrong.Size, true)
	if _, err = io.ReadAll(reader); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("digest mismatch = %v", err)
	}
	_ = reader.Close()

	reader = New(context.Background(), io.NopCloser(bytes.NewReader(body[:5])), blob, blob.Size, false)
	if _, err = io.ReadAll(reader); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("short range = %v", err)
	}
	_ = reader.Close()

	rangeBody := body[2:8]
	reader = New(context.Background(), io.NopCloser(bytes.NewReader(rangeBody)), wrong, int64(len(rangeBody)), false)
	if got, err = io.ReadAll(reader); err != nil || !bytes.Equal(got, rangeBody) {
		t.Fatalf("range read = %q, %v", got, err)
	}
	_ = reader.Close()
}

func TestReaderTerminalConditions(t *testing.T) {
	body := []byte("exact body")
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}

	reader := New(context.Background(), &terminalReader{body: body, err: io.EOF}, blob, blob.Size, true)
	if got, err := io.ReadAll(reader); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("data with terminal EOF = %q, %v", got, err)
	}
	_ = reader.Close()

	sentinel := errors.New("terminal backend failure")
	reader = New(context.Background(), &terminalReader{body: body, err: sentinel}, blob, blob.Size, true)
	if got, err := io.ReadAll(reader); !errors.Is(err, sentinel) || !bytes.Equal(got, body) {
		t.Fatalf("data with terminal failure = %q, %v", got, err)
	}
	_ = reader.Close()

	extended := append(append([]byte(nil), body...), '!')
	reader = New(context.Background(), io.NopCloser(bytes.NewReader(extended)), blob, blob.Size, true)
	if _, err := io.ReadAll(reader); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("extended stream = %v", err)
	}
	_ = reader.Close()

	reader = New(context.Background(), io.NopCloser(stalledReader{}), content.Blob{}, 0, false)
	if _, err := io.ReadAll(reader); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("stalled terminal probe = %v", err)
	}
	_ = reader.Close()

	reader = New(context.Background(), io.NopCloser(errorReader{err: sentinel}), content.Blob{}, 0, false)
	if _, err := io.ReadAll(reader); !errors.Is(err, sentinel) {
		t.Fatalf("terminal probe failure = %v", err)
	}
	_ = reader.Close()

	reader = New(context.Background(), &probeReader{value: 'x', probeErr: sentinel}, content.Blob{Size: 1}, 1, false)
	if _, err := io.ReadAll(reader); !errors.Is(err, sentinel) {
		t.Fatalf("backend terminal probe failure = %v", err)
	}
	_ = reader.Close()

	probeContext, probeCancel := context.WithCancel(context.Background())
	reader = New(probeContext, &probeReader{value: 'x', probeErr: io.EOF, cancel: probeCancel}, content.Blob{Size: 1}, 1, false)
	if _, err := io.ReadAll(reader); !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal probe cancellation = %v", err)
	}
	_ = reader.Close()

	reader = New(context.Background(), io.NopCloser(invalidCountReader(2)), content.Blob{Size: 1}, 1, false)
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("invalid backend count = %v", err)
	}
	_ = reader.Close()

	ctx, cancel := context.WithCancel(context.Background())
	reader = New(ctx, io.NopCloser(bytes.NewReader(body)), blob, blob.Size, true)
	cancel()
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled read = %v", err)
	}
	_ = reader.Close()

	reader = New(context.Background(), io.NopCloser(bytes.NewReader(body)), blob, blob.Size, true)
	if n, err := reader.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatal(err)
	}
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("settled read = %d, %v", n, err)
	}
	_ = reader.Close()

	if equal([]byte{1}, []byte{1, 2}) {
		t.Fatal("different-length values compare equal")
	}
}

func TestWriteVerification(t *testing.T) {
	body := bytes.Repeat([]byte("write verification"), 10_000)
	blob := content.Blob{SHA256: sha256.Sum256(body), Size: int64(len(body))}
	var destination bytes.Buffer
	if err := Write(context.Background(), &destination, bytes.NewReader(body), blob); err != nil || !bytes.Equal(destination.Bytes(), body) {
		t.Fatalf("write = %d bytes, %v", destination.Len(), err)
	}

	empty := content.Blob{SHA256: sha256.Sum256(nil)}
	if err := Write(context.Background(), io.Discard, bytes.NewReader(nil), empty); err != nil {
		t.Fatalf("empty write = %v", err)
	}
	if err := Write(nil, io.Discard, bytes.NewReader(nil), empty); !errors.Is(err, content.ErrInvalid) { //nolint:staticcheck // Verify that the API rejects a nil context.
		t.Fatalf("nil context = %v", err)
	}
	if err := Write(context.Background(), nil, bytes.NewReader(nil), empty); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("nil destination = %v", err)
	}
	if err := Write(context.Background(), io.Discard, nil, empty); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("nil source = %v", err)
	}
	if err := Write(context.Background(), io.Discard, bytes.NewReader(nil), content.Blob{Size: -1}); !errors.Is(err, content.ErrInvalid) {
		t.Fatalf("invalid blob = %v", err)
	}

	if err := Write(context.Background(), io.Discard, bytes.NewReader(body[:len(body)-1]), blob); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("short source = %v", err)
	}
	if err := Write(context.Background(), io.Discard, bytes.NewReader(append(append([]byte(nil), body...), '!')), blob); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("long source = %v", err)
	}
	wrong := blob
	wrong.SHA256[0] ^= 0xff
	if err := Write(context.Background(), io.Discard, bytes.NewReader(body), wrong); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("digest mismatch = %v", err)
	}

	sentinel := errors.New("terminal source failure")
	if err := Write(context.Background(), io.Discard, &terminalReader{body: body, err: sentinel}, blob); !errors.Is(err, sentinel) {
		t.Fatalf("terminal source failure = %v", err)
	}
	if err := Write(context.Background(), io.Discard, &terminalReader{body: body, err: io.EOF}, blob); err != nil {
		t.Fatalf("terminal source EOF = %v", err)
	}
	if err := Write(context.Background(), io.Discard, stalledReader{}, blob); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("stalled source = %v", err)
	}
	if err := Write(context.Background(), shortWriter{}, bytes.NewReader(body), blob); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short destination = %v", err)
	}
	if err := Write(context.Background(), errorWriter{err: sentinel}, bytes.NewReader(body), blob); !errors.Is(err, sentinel) {
		t.Fatalf("destination failure = %v", err)
	}
	if err := Write(context.Background(), io.Discard, invalidCountReader(-1), content.Blob{Size: 1}); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("negative source count = %v", err)
	}
	if err := Write(context.Background(), io.Discard, invalidCountReader(2), content.Blob{Size: 1}); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("large source count = %v", err)
	}
	if err := Write(context.Background(), invalidCountWriter(-1), bytes.NewReader([]byte{0}), content.Blob{Size: 1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("negative destination count = %v", err)
	}
	if err := Write(context.Background(), invalidCountWriter(2), bytes.NewReader([]byte{0}), content.Blob{Size: 1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("large destination count = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Write(canceled, io.Discard, bytes.NewReader(body), blob); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled write = %v", err)
	}
	if err := Write(context.Background(), io.Discard, invalidCountReader(2), empty); !errors.Is(err, content.ErrCorrupt) {
		t.Fatalf("large terminal source count = %v", err)
	}
	if err := Write(context.Background(), io.Discard, errorReader{err: sentinel}, empty); !errors.Is(err, sentinel) {
		t.Fatalf("terminal probe source failure = %v", err)
	}
	if err := Write(context.Background(), io.Discard, stalledReader{}, empty); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("stalled terminal source = %v", err)
	}
	probeContext, probeCancel := context.WithCancel(context.Background())
	if err := Write(probeContext, io.Discard, cancelingReader{body: body, cancel: probeCancel}, blob); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled after source read = %v", err)
	}
	probeContext, probeCancel = context.WithCancel(context.Background())
	probeCancel()
	if err := expectSourceEOF(probeContext, bytes.NewReader(nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled terminal probe = %v", err)
	}
}

func TestCancellationClosesBlockedReader(t *testing.T) {
	underlying := newBlockingReader()
	ctx, cancel := context.WithCancel(context.Background())
	reader := New(ctx, underlying, content.Blob{Size: 1}, 1, false)
	result := make(chan error, 1)
	go func() {
		_, err := reader.Read(make([]byte, 1))
		result <- err
	}()
	select {
	case <-underlying.started:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked read = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock read")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
}

func TestCloseUnblocksConcurrentRead(t *testing.T) {
	underlying := newBlockingReader()
	reader := New(context.Background(), underlying, content.Blob{Size: 1}, 1, false)
	result := make(chan error, 1)
	go func() {
		_, err := reader.Read(make([]byte, 1))
		result <- err
	}()
	select {
	case <-underlying.started:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked read succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock read")
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
}

type blockingReader struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingReader() *blockingReader {
	return &blockingReader{started: make(chan struct{}), closed: make(chan struct{})}
}

func (reader *blockingReader) Read([]byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.closed
	return 0, errors.New("closed")
}

func (reader *blockingReader) Close() error {
	select {
	case <-reader.closed:
	default:
		close(reader.closed)
	}
	return nil
}

type terminalReader struct {
	body []byte
	err  error
}

func (reader *terminalReader) Read(buffer []byte) (int, error) {
	n := copy(buffer, reader.body)
	reader.body = reader.body[n:]
	if len(reader.body) != 0 {
		return n, nil
	}
	return n, reader.err
}

func (*terminalReader) Close() error { return nil }

type stalledReader struct{}

func (stalledReader) Read([]byte) (int, error) { return 0, nil }

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) { return len(value) - 1, nil }

type errorWriter struct{ err error }

func (writer errorWriter) Write([]byte) (int, error) { return 0, writer.err }

type invalidCountReader int

func (reader invalidCountReader) Read([]byte) (int, error) { return int(reader), nil }

type invalidCountWriter int

func (writer invalidCountWriter) Write([]byte) (int, error) { return int(writer), nil }

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

type probeReader struct {
	value    byte
	read     bool
	probeErr error
	cancel   context.CancelFunc
}

func (reader *probeReader) Read(buffer []byte) (int, error) {
	if !reader.read {
		reader.read = true
		buffer[0] = reader.value
		return 1, nil
	}
	if reader.cancel != nil {
		reader.cancel()
	}
	return 0, reader.probeErr
}

func (*probeReader) Close() error { return nil }

type cancelingReader struct {
	body   []byte
	cancel context.CancelFunc
}

func (reader cancelingReader) Read(buffer []byte) (int, error) {
	n := copy(buffer, reader.body)
	reader.cancel()
	return n, nil
}
