// Typed client for the Xila API. `paths` (src/schema.d.ts) is generated from
// the server's OpenAPI spec by `make clients`; do not edit it by hand.
//
//   import { createXilaClient } from '@xilasec/client';
//   const xila = createXilaClient({ baseUrl: 'https://xila.example.com/api/v1', token });
//   const { data, error } = await xila.GET('/projects/{projectID}/findings', {
//     params: { path: { projectID }, query: { severity: 'critical' } },
//   });
//
// Paths, parameters, request bodies and response bodies are all checked by the
// compiler against the spec of the server version the client was generated from.
import createClient, { type Client, type ClientOptions } from 'openapi-fetch';
import type { components, paths, operations } from './schema.js';

export type { components, paths, operations };
/** A schema from the spec: `Schema<'Finding'>`. */
export type Schema<Name extends keyof components['schemas']> = components['schemas'][Name];

export interface XilaClientOptions extends ClientOptions {
	/** An API token (`xila_…`) or session JWT, sent as `Authorization: Bearer`. */
	token?: string;
}

export function createXilaClient({ token, headers, ...opts }: XilaClientOptions = {}): Client<paths> {
	return createClient<paths>({
		...opts,
		headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(headers as Record<string, string> | undefined) },
	});
}
