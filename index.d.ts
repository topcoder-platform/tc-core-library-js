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
