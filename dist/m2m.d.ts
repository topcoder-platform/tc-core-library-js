import { HttpOptions } from './http';
export interface M2MConfiguration extends HttpOptions {
    AUTH0_URL?: string;
    AUTH0_AUDIENCE?: string;
    AUTH0_PROXY_SERVER_URL?: string;
    AUTH_SCOPE?: string;
    AUTH_PROVIDER?: string;
    AUTH_CONTENT_TYPE?: string;
    TOKEN_CACHE_TIME?: number | string;
}
export interface M2MClient {
    getMachineToken(clientId: string, clientSecret: string): Promise<string>;
    clearCache(): void;
}
/** Creates an isolated OAuth client used for outbound service authentication.
 * @param config Explicit token/proxy endpoints, audience and HTTP limits.
 * @returns Client with bounded, expiration-aware caching and concurrent request deduplication.
 * @throws Error for invalid configuration; token requests reject with sanitized HttpError.
 */
export declare function createM2MClient(config: M2MConfiguration): M2MClient;
