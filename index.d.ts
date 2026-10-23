export interface Principal {
  kind: 'service' | 'user'; isMachine: boolean; scopes: string[]; roles: string[];
  userId?: number; handle?: string; email?: string; clientId?: string; azpHash?: number;
  iss: string; sub: string; aud: string | string[]; iat: number; exp: number;
  [claim: string]: unknown;
}
export interface AuthOptions { [setting: string]: unknown; }
export const auth: {
  createValidator(options?: AuthOptions): {verify(token: string): Promise<Principal>};
  hasScopes(user: Principal | undefined, required: string[], mode?: 'all' | 'any'): boolean;
  /** True when USE_KEYCLOAK selects Keycloak; false (Auth0) when unset or "false". Throws for other values. */
  useKeycloak(options?: AuthOptions): boolean;
  /** Active provider's endpoint, audience and credentials under tc-bus-api-wrapper's AUTH0_* names. */
  wrapperSettings(options?: AuthOptions): {
    AUTH0_URL?: string; AUTH0_AUDIENCE?: string; AUTH0_PROXY_SERVER_URL?: string;
    AUTH0_CLIENT_ID?: string; AUTH0_CLIENT_SECRET?: string;
  };
  /** Keycloak provider when USE_KEYCLOAK=true, otherwise the Auth0 provider. */
  m2m(options?: AuthOptions): {
    getMachineToken(clientId?: string, clientSecret?: string, scope?: string): Promise<string>;
    clearCache(): void;
  };
  verifier(...args: unknown[]): {validateToken(token: string, secret: unknown, callback: (error?: Error, user?: Principal) => void): void};
};
export const middleware: {
  jwtAuthenticator(options?: AuthOptions): (req: any, res: any, next: (error?: Error) => void) => void;
  logger: any; permissions: any;
};
export const Authorizer: any;
export const util: any;
export const logger: any;
