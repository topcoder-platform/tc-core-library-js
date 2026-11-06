"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HttpError = void 0;
exports.endpoint = endpoint;
exports.postJson = postJson;
const node_http_1 = require("node:http");
const node_https_1 = require("node:https");
/** Safe operational failure without response bodies, URLs, tokens or credentials. */
class HttpError extends Error {
    status;
    /** Creates an operational error for shared HTTP clients. No exceptions are raised.
     * @param operation Safe operation label. @param status HTTP status, if available.
     */
    constructor(operation, status) {
        super(`${operation}${status ? ` (HTTP ${status})` : ''}`);
        this.status = status;
        this.name = 'HttpError';
    }
}
exports.HttpError = HttpError;
/** Validates a server-configured endpoint used by auth and bus clients.
 * @param value Absolute endpoint. @param allowHttp Explicit internal-network opt-in.
 * @returns Parsed URL. @throws Error for unsafe protocols, credentials or fragments.
 */
function endpoint(value, allowHttp = false) {
    let url;
    try {
        url = new URL(value);
    }
    catch {
        throw new Error('Invalid endpoint configuration');
    }
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && (loopback || allowHttp))) ||
        url.username || url.password || url.hash || url.search) {
        throw new Error('Endpoint must use HTTPS without credentials, query or fragment');
    }
    return url;
}
/** Sends JSON through Node's HTTP clients without depending on global fetch or native Promise extensions.
 * @param url Validated endpoint. @param body Serialized JSON payload. @param headers Request headers.
 * @param signal Combined request and caller deadline, including response-body consumption.
 * @returns Status and parsed JSON body. @throws HttpError or a transport/JSON error for the caller to sanitize.
 */
function postWithNodeHttp(url, body, headers, signal) {
    return new Promise((resolve, reject) => {
        const request = (new URL(url).protocol === 'https:' ? node_https_1.request : node_http_1.request)(url, {
            method: 'POST', signal,
            headers: { ...headers, ...(body === undefined ? {} : { 'Content-Length': Buffer.byteLength(body) }) },
        }, response => {
            response.on('error', reject);
            const status = response.statusCode ?? 0;
            if (status < 200 || status >= 300) {
                response.destroy();
                reject(new HttpError('Request rejected', status));
                return;
            }
            const chunks = [];
            let size = 0;
            response.on('data', (chunk) => {
                size += chunk.length;
                if (size > 1024 * 1024) {
                    reject(new HttpError('Response too large'));
                    response.destroy();
                    return;
                }
                chunks.push(chunk);
            });
            response.on('end', () => {
                try {
                    const text = Buffer.concat(chunks).toString('utf8');
                    resolve({ status, body: text ? JSON.parse(text) : undefined });
                }
                catch (error) {
                    reject(error);
                }
            });
        });
        request.on('error', reject);
        request.end(body);
    });
}
/** Performs one bounded JSON POST, with no redirects or implicit retries.
 * Uses Node's HTTP clients by default so hosts may replace global Promise with Bluebird.
 * An explicitly injected fetch implementation retains the existing testing/custom transport contract.
 * @param url Validated endpoint. @param body JSON payload. @param options Network settings.
 * @param token Optional bearer token. @param signal Optional caller deadline.
 * @returns Status and parsed JSON body. @throws HttpError for HTTP, timeout or malformed responses.
 */
async function postJson(url, body, options, token, signal) {
    const timeout = options.timeoutMs ?? 10000;
    if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 120000)
        throw new Error('Invalid HTTP timeout');
    const deadline = AbortSignal.timeout(timeout);
    const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
    try {
        const headers = { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) };
        const serialized = JSON.stringify(body);
        if (!options.fetch)
            return await postWithNodeHttp(url, serialized, headers, combined);
        const response = await options.fetch(url, {
            method: 'POST', redirect: 'error', signal: combined,
            headers, body: serialized,
        });
        if (!response.ok) {
            await response.body?.cancel();
            throw new HttpError('Request rejected', response.status);
        }
        const reader = response.body?.getReader();
        const chunks = [];
        let size = 0;
        if (reader) {
            while (true) {
                const { done, value } = await reader.read();
                if (done)
                    break;
                size += value.byteLength;
                if (size > 1024 * 1024) {
                    await reader.cancel();
                    throw new HttpError('Response too large');
                }
                chunks.push(value);
            }
        }
        const text = Buffer.concat(chunks).toString('utf8');
        return { status: response.status, body: text ? JSON.parse(text) : undefined };
    }
    catch (error) {
        if (error instanceof HttpError)
            throw error;
        throw new HttpError('Request failed or timed out');
    }
}
//# sourceMappingURL=http.js.map