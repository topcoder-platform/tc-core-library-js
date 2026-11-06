/** Safe operational failure without response bodies, URLs, tokens or credentials. */
export declare class HttpError extends Error {
    readonly status?: number | undefined;
    /** Creates an operational error for shared HTTP clients. No exceptions are raised.
     * @param operation Safe operation label. @param status HTTP status, if available.
     */
    constructor(operation: string, status?: number | undefined);
}
export interface HttpOptions {
    timeoutMs?: number;
    allowInsecureHttp?: boolean;
    fetch?: typeof fetch;
}
/** Validates a server-configured endpoint used by auth and bus clients.
 * @param value Absolute endpoint. @param allowHttp Explicit internal-network opt-in.
 * @returns Parsed URL. @throws Error for unsafe protocols, credentials or fragments.
 */
export declare function endpoint(value: string, allowHttp?: boolean): URL;
/** Performs one bounded JSON POST, with no redirects or implicit retries.
 * Uses Node's HTTP clients by default so hosts may replace global Promise with Bluebird.
 * An explicitly injected fetch implementation retains the existing testing/custom transport contract.
 * @param url Validated endpoint. @param body JSON payload. @param options Network settings.
 * @param token Optional bearer token. @param signal Optional caller deadline.
 * @returns Status and parsed JSON body. @throws HttpError for HTTP, timeout or malformed responses.
 */
export declare function postJson(url: string, body: unknown, options: HttpOptions, token?: string, signal?: AbortSignal): Promise<{
    status: number;
    body: unknown;
}>;
