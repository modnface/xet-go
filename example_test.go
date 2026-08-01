package xet_test

import (
	"fmt"
	"net/url"

	xet "github.com/jacobwoliver/xet-go"
	"github.com/jacobwoliver/xet-go/xetcas"
)

func ExampleNewClient() {
	endpoint, err := url.Parse("https://cas.example.invalid")
	if err != nil {
		panic(err)
	}
	protocol, err := xetcas.New(
		xetcas.NewStaticAccess(endpoint, "already-issued-token"),
		xetcas.Options{SessionID: "example-operation"},
	)
	if err != nil {
		panic(err)
	}
	client, err := xet.NewClient(protocol, xet.Options{})
	if err != nil {
		panic(err)
	}
	fmt.Println(client != nil)
	// Output: true
}
