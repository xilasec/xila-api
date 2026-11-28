// Command openapi30 writes the OpenAPI 3.0 view of the embedded spec (see
// apidoc.OpenAPI30), the input the Go client generator reads. `make clients`
// runs it; it is a development tool and is not shipped.
//
//	go run ./internal/tools/openapi30 -o clients/go/openapi30.yaml
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/xilasec/xila-api/internal/apidoc"
)

func main() {
	out := flag.String("o", "", "output file (default stdout)")
	flag.Parse()
	spec, err := apidoc.OpenAPI30()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out == "" {
		_, err = os.Stdout.Write(spec)
	} else {
		err = os.WriteFile(*out, spec, 0o644) //nolint:gosec // G306: a generated file committed to the repository
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
