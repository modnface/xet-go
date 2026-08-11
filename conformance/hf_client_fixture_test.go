package conformance_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type hubTranscript struct {
	Schema   int               `json:"schema"`
	Repo     string            `json:"repo"`
	Revision string            `json:"revision"`
	Runtime  map[string]string `json:"runtime"`
	Records  []struct {
		Operation string `json:"operation"`
		Request   struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"request"`
		Response struct {
			Status int             `json:"status"`
			Body   json.RawMessage `json:"body"`
		} `json:"response"`
	} `json:"records"`
}

func TestPinnedOfficialHubPublicReadTranscript(t *testing.T) {
	encoded, err := os.ReadFile("hf-client/public-read-transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	var transcript hubTranscript
	if err = json.Unmarshal(encoded, &transcript); err != nil {
		t.Fatal(err)
	}
	if transcript.Schema != 1 || transcript.Repo != "hf-internal-testing/tiny-random-bert" ||
		transcript.Revision != "f171d7baecaf37b5da5a3616d8833b9969753535" {
		t.Fatalf("unexpected public transcript identity: %#v", transcript)
	}
	if transcript.Runtime["huggingface_hub"] != "1.27.0" || transcript.Runtime["hf_xet"] != "1.6.0" {
		t.Fatalf("unexpected official client pins: %#v", transcript.Runtime)
	}
	wanted := map[string]string{
		"model-info-main":      "GET /api/models/hf-internal-testing/tiny-random-bert?blobs=true",
		"model-info-immutable": "GET /api/models/hf-internal-testing/tiny-random-bert/revision/f171d7baecaf37b5da5a3616d8833b9969753535?blobs=true",
		"tree-recursive":       "GET /api/models/hf-internal-testing/tiny-random-bert/tree/f171d7baecaf37b5da5a3616d8833b9969753535?recursive=true&expand=false",
		"head-ordinary":        "HEAD /hf-internal-testing/tiny-random-bert/resolve/f171d7baecaf37b5da5a3616d8833b9969753535/config.json",
		"head-xet":             "HEAD /hf-internal-testing/tiny-random-bert/resolve/f171d7baecaf37b5da5a3616d8833b9969753535/pytorch_model.bin",
		"xet-read-token":       "GET /api/models/hf-internal-testing/tiny-random-bert/xet-read-token/f171d7baecaf37b5da5a3616d8833b9969753535",
		"get-ordinary-range":   "GET /hf-internal-testing/tiny-random-bert/resolve/f171d7baecaf37b5da5a3616d8833b9969753535/config.json",
	}
	found := make(map[string]bool, len(wanted))
	for _, record := range transcript.Records {
		if record.Response.Status < 200 || record.Response.Status >= 400 {
			t.Fatalf("captured %s status = %d", record.Operation, record.Response.Status)
		}
		if route, required := wanted[record.Operation]; required && route == record.Request.Method+" "+record.Request.Path {
			found[record.Operation] = true
		}
		if record.Operation == "xet-read-token" {
			var body struct {
				AccessToken string `json:"accessToken"`
				CASURL      string `json:"casUrl"`
				ExpiresAt   int64  `json:"exp"`
			}
			if err := json.Unmarshal(record.Response.Body, &body); err != nil {
				t.Fatal(err)
			}
			if body.AccessToken != "<redacted>" || body.CASURL != "https://cas-server.xethub.hf.co" || body.ExpiresAt <= 0 {
				t.Fatalf("invalid sanitized Xet token fixture: %#v", body)
			}
		}
	}
	for operation := range wanted {
		if !found[operation] {
			t.Errorf("required captured route %q is absent", operation)
		}
	}
	lower := strings.ToLower(string(encoded))
	for _, secretMarker := range []string{"x-amz-signature=", "signature=", "policy=", "key-pair-id=", "bearer ey"} {
		if strings.Contains(lower, secretMarker) {
			t.Errorf("transcript contains an unsanitized capability marker %q", secretMarker)
		}
	}
}
