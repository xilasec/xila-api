// Package xila is a generated Go client for the Xila API.
//
// It is generated from the API's OpenAPI description (internal/apidoc) by
// `make clients`; CI fails when it is out of date. Every operation is a method
// named after its operationId, in two flavours: Client returns the raw
// *http.Response, ClientWithResponses decodes the documented JSON bodies.
//
//	c, err := xila.NewClientWithResponses("https://xila.example.com/api/v1",
//		xila.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
//			req.Header.Set("Authorization", "Bearer "+os.Getenv("XILA_TOKEN"))
//			return nil
//		}))
//	res, err := c.ListProjectsWithResponse(ctx, &xila.ListProjectsParams{})
//
// Separate module, so the generator's runtime dependency stays out of the
// server's go.mod.
package xila
