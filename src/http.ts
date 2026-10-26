/** Safe operational failure without response bodies, URLs, tokens or credentials. */
export class HttpError extends Error {
  /** Creates an operational error for shared HTTP clients. No exceptions are raised.
   * @param operation Safe operation label. @param status HTTP status, if available.
   */
  constructor(operation: string, public readonly status?: number) {
    super(`${operation}${status ? ` (HTTP ${status})` : ''}`);
    this.name = 'HttpError';
  }
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
export function endpoint(value: string, allowHttp = false): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('Invalid endpoint configuration'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && (loopback || allowHttp))) ||
      url.username || url.password || url.hash || url.search) {
    throw new Error('Endpoint must use HTTPS without credentials, query or fragment');
  }
  return url;
}

/** Performs one bounded JSON POST, with no redirects or implicit retries.
 * @param url Validated endpoint. @param body JSON payload. @param options Network settings.
 * @param token Optional bearer token. @param signal Optional caller deadline.
 * @returns Status and parsed JSON body. @throws HttpError for HTTP, timeout or malformed responses.
 */
export async function postJson(url: string, body: unknown, options: HttpOptions, token?: string, signal?: AbortSignal): Promise<{ status: number; body: unknown }> {
  const timeout = options.timeoutMs ?? 10000;
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 120000) throw new Error('Invalid HTTP timeout');
  const deadline = AbortSignal.timeout(timeout);
  const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  try {
    const response = await (options.fetch ?? fetch)(url, {
      method: 'POST', redirect: 'error', signal: combined,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new HttpError('Request rejected', response.status);
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 1024 * 1024) { await reader.cancel(); throw new HttpError('Response too large'); }
        chunks.push(value);
      }
    }
    const text = Buffer.concat(chunks).toString('utf8');
    return { status: response.status, body: text ? JSON.parse(text) as unknown : undefined };
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError('Request failed or timed out');
  }
}
