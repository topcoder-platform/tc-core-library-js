"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveBusEventsUrl = resolveBusEventsUrl;
exports.createBusApiClient = createBusApiClient;
const http_1 = require("./http");
const m2m_1 = require("./m2m");
/** Resolves API base, /bus base or full /bus/events configuration without duplicate suffixes.
 * @param value Server-configured bus endpoint. @param allowHttp Internal HTTP opt-in.
 * @returns Events URL. @throws Error for invalid endpoints.
 */
function resolveBusEventsUrl(value, allowHttp = false) {
    const url = (0, http_1.endpoint)(value, allowHttp);
    const path = url.pathname.replace(/\/+$/, '');
    url.pathname = path.endsWith('/bus/events') || path.endsWith('/eventBus') ? path : path.endsWith('/bus') ? `${path}/events` : `${path}/bus/events`;
    return url.toString();
}
/** Creates the single bus publisher used by services; construction performs no I/O.
 * @param config Bus endpoint, M2M credentials or existing token provider, and HTTP limits.
 * @returns Publisher preserving event envelopes and message keys, with no automatic POST retries.
 * @throws Error for missing configuration; post methods reject with sanitized HttpError.
 */
function createBusApiClient(config) {
    config = { ...config };
    if (!config.BUSAPI_URL)
        throw new Error('BUSAPI_URL is required');
    const url = resolveBusEventsUrl(config.BUSAPI_URL, config.allowInsecureHttp);
    const m2m = config.getToken ? undefined : (0, m2m_1.createM2MClient)(config);
    if (!config.getToken && (!config.AUTH0_CLIENT_ID || !config.AUTH0_CLIENT_SECRET))
        throw new Error('Bus M2M credentials are required');
    const tokenProvider = config.getToken ?? (() => m2m.getMachineToken(config.AUTH0_CLIENT_ID, config.AUTH0_CLIENT_SECRET));
    /** Validates and publishes the supplied event, returning the accepted HTTP result or throwing HttpError. */
    async function postEvent(event) {
        if (!event || typeof event.topic !== 'string' || !event.topic.trim() ||
            typeof event.originator !== 'string' || !event.originator.trim() ||
            typeof event.timestamp !== 'string' || !Number.isFinite(Date.parse(event.timestamp)) ||
            event['mime-type'] !== 'application/json' || !Object.hasOwn(event, 'payload') ||
            (event.key !== undefined && typeof event.key !== 'string'))
            throw new Error('Invalid bus event envelope');
        try {
            const token = await tokenProvider();
            if (!token || /\s/.test(token))
                throw new http_1.HttpError('Invalid access token');
            return await (0, http_1.postJson)(url, event, config, token);
        }
        catch (error) {
            if (error instanceof http_1.HttpError && error.status === 401)
                m2m?.clearCache();
            if (error instanceof http_1.HttpError)
                throw error;
            throw new http_1.HttpError('Bus publish failed');
        }
    }
    return { postEvent };
}
//# sourceMappingURL=bus.js.map