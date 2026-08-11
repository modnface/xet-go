package catalog_test

import (
	"testing"

	"github.com/jmwoliver/xet-go/catalog"
	"github.com/jmwoliver/xet-go/model"
)

func TestExpectRefClonesOID(t *testing.T) {
	oid, err := model.ParseOID("1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	expectation := catalog.ExpectRef("main", &oid)
	oid[0] = 2
	if expectation.Name != "main" || expectation.OID == nil || expectation.OID[0] != 0x11 {
		t.Fatalf("ref expectation = %#v", expectation)
	}
	absent := catalog.ExpectRef("main", nil)
	if absent.OID != nil {
		t.Fatalf("absent ref expectation = %#v", absent)
	}
}
