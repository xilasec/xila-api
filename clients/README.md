# Xila API clients

Generated from the API's OpenAPI description (`internal/apidoc/openapi.yaml`) by
`make clients`. CI (`make clients-check`) fails when they are out of date. Method
and type names come from each operation's `operationId`, so renaming one is a
breaking change for client users.

| Client | Package | Generator |
|---|---|---|
| Go | `github.com/xilasec/xila-api/clients/go` (own module) | oapi-codegen v2.8.1, from the OpenAPI 3.0 view (`go run ./internal/tools/openapi30`), since it does not read 3.1 |
| TypeScript | `clients/typescript` (`@xilasec/client`) | openapi-typescript 7.13.0 types + an openapi-fetch wrapper |

The 3.0 view is mechanical: nullable unions become `nullable: true`, and the
two `string | number` custom-field value schemas become untyped (`any`), because
3.0 has no union of primitives.

## Go

```go
c, _ := xila.NewClientWithResponses("https://xila.example.com/api/v1",
	xila.WithRequestEditorFn(func(ctx context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+os.Getenv("XILA_TOKEN"))
		return nil
	}))
res, err := c.ListProjectFindingsWithResponse(ctx, projectID, &xila.ListProjectFindingsParams{})
```

## TypeScript

```ts
import { createXilaClient } from '@xilasec/client';
const xila = createXilaClient({ baseUrl: 'https://xila.example.com/api/v1', token });
const { data } = await xila.GET('/projects/{projectID}/findings', { params: { path: { projectID } } });
```

