import { HttpOptions } from './http';
import { M2MConfiguration } from './m2m';
export interface BusApiEvent<T = unknown> {
    topic: string;
    originator: string;
    timestamp: string;
    'mime-type': string;
    payload: T;
    key?: string;
}
export interface BusApiConfiguration extends M2MConfiguration, HttpOptions {
    BUSAPI_URL?: string;
    AUTH0_CLIENT_ID?: string;
    AUTH0_CLIENT_SECRET?: string;
    KAFKA_ERROR_TOPIC?: string;
    getToken?: () => Promise<string>;
}
export interface BusApiResponse {
    status: number;
    body: unknown;
}
export interface BusApiClient {
    postEvent<T>(event: BusApiEvent<T>): Promise<BusApiResponse>;
}
/** Resolves API base, /bus base or full /bus/events configuration without duplicate suffixes.
 * @param value Server-configured bus endpoint. @param allowHttp Internal HTTP opt-in.
 * @returns Events URL. @throws Error for invalid endpoints.
 */
export declare function resolveBusEventsUrl(value: string, allowHttp?: boolean): string;
/** Creates the single bus publisher used by services; construction performs no I/O.
 * @param config Bus endpoint, M2M credentials or existing token provider, and HTTP limits.
 * @returns Publisher preserving event envelopes and message keys, with no automatic POST retries.
 * @throws Error for missing configuration; post methods reject with sanitized HttpError.
 */
export declare function createBusApiClient(config: BusApiConfiguration): BusApiClient;
