package xet

import (
	"context"
	"testing"
)

func TestFlushCurrentReleasesFinalizedPayloads(t *testing.T) {
	client := newTestEngine(t, newMemoryProtocol())
	batch, err := client.NewUploadBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pending := batch.current
	pending.chunks = [][]byte{[]byte("payload retained by placements")}
	pending.rawBytes = len(pending.chunks[0])
	pending.fileBoundaries = []int{0}

	if err := batch.flushCurrent(); err != nil {
		batch.Abort(err)
		t.Fatal(err)
	}
	if pending.chunks != nil || pending.fileBoundaries != nil {
		batch.Abort(context.Canceled)
		batch.workers.Wait()
		t.Fatal("finalized xorb retained source payloads")
	}
	batch.Abort(context.Canceled)
	batch.workers.Wait()
}
