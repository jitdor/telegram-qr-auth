// Types for telegram-qr-auth/oidc.

import type { Gate, AuthUser, TelegramQrAuth, DurableObjectNamespaceLike } from "./index";

export type ClientType = "public" | "confidential";

export interface OidcClient {
  client_id: string;
  client_name: string;
  client_secret?: string;
  redirect_uris: string[];
  type?: ClientType;
  scopes?: string[];
  /** Skips the consent screen. Only for apps you ship yourself. */
  first_party?: boolean;
  pairwise?: boolean;
  authorize?: (user: { id: number; username?: string }, ctx: { request?: Request; client: OidcClient }) => ReturnType<Gate>;
  post_logout_redirect_uris?: string[];
}

export interface ClientRegistry {
  get(clientId: string): Promise<OidcClient | null>;
}

export declare class StaticClientRegistry implements ClientRegistry {
  constructor(clients: OidcClient[]);
  get(clientId: string): Promise<OidcClient | null>;
}
export declare class StoreClientRegistry implements ClientRegistry {
  constructor(store: { get(key: string): Promise<unknown> | unknown }, options?: object);
  get(clientId: string): Promise<OidcClient | null>;
}

export declare const PUBLIC_CLIENT: "public";
export declare const CONFIDENTIAL_CLIENT: "confidential";
export declare function validateClient(client: OidcClient): OidcClient;
export declare function matchRedirectUri(client: OidcClient, candidate: string): string | null;
export declare function verifyClientSecret(client: OidcClient, presented: string | undefined): Promise<boolean>;
export declare function subjectFor(client: OidcClient, userId: string | number, pairwiseSalt?: string): Promise<string>;
export declare function sectorIdentifierFor(client: OidcClient): string;

// ---- keys and JWTs ----

export type Jwk = Record<string, unknown>;
export interface SigningKey {
  kid: string;
  [field: string]: unknown;
}
export declare const SIGNING_ALG: "ES256";
export declare function generateSigningKey(): Promise<Jwk>;
export declare function loadSigningKeys(input: Jwk | string | Array<Jwk | string>): Promise<SigningKey[]>;
export declare function toJwks(keys: SigningKey[]): { keys: Jwk[] };
export declare function jwkThumbprint(jwk: Jwk): Promise<string>;
export declare function importPublicJwk(jwk: Jwk): Promise<CryptoKey>;
export declare function signJwt(claims: Record<string, unknown>, key: SigningKey, typ?: string): Promise<string>;
export declare function verifyJwt(
  token: string,
  options: { keys: SigningKey[]; issuer: string; audience: string; clockToleranceSeconds?: number; now?: () => number; typ?: string }
): Promise<Record<string, any> | null>;
export declare function decodeJwt(token: string): { header: Record<string, any>; payload: Record<string, any> } | null;

// ---- PKCE ----

export declare const S256: "S256";
export declare function createPkcePair(): Promise<{ verifier: string; challenge: string }>;
export declare function deriveChallenge(verifier: string): Promise<string>;
export declare function verifyChallenge(verifier: string | undefined, challenge: string, method?: string): Promise<boolean>;
export declare function isValidChallenge(challenge: unknown): boolean;
export declare function isValidVerifier(verifier: unknown): boolean;

// ---- stores ----

export type RefreshRotation =
  | { status: "ok"; payload: Record<string, any> }
  | { status: "reused"; payload: Record<string, any> }
  | { status: "missing" };

/**
 * `consumeCode` and `rotateRefreshToken` must be atomic against themselves. Memory, D1 and DO
 * stores are; KvOidcStore is best-effort only.
 */
export interface OidcStore {
  saveRequest(id: string, request: Record<string, any>, ttlSeconds?: number): Promise<void>;
  peekRequest(id: string): Promise<Record<string, any> | null>;
  takeRequest(id: string): Promise<Record<string, any> | null>;
  saveCode(code: string, payload: Record<string, any>, ttlSeconds?: number): Promise<void>;
  consumeCode(code: string): Promise<Record<string, any> | null>;
  saveRefreshToken(token: string, payload: Record<string, any>, ttlSeconds: number): Promise<void>;
  getRefreshToken(token: string): Promise<Record<string, any> | null>;
  rotateRefreshToken(token: string): Promise<RefreshRotation>;
  deleteRefreshToken(token: string): Promise<void>;
  revokeFamily(familyId: string): Promise<void>;
  getConsent(userId: string | number, clientId: string): Promise<{ scopes: string[]; grantedAt: number } | null>;
  saveConsent(userId: string | number, clientId: string, scopes: string[]): Promise<void>;
  revokeConsent(userId: string | number, clientId: string): Promise<void>;
}

export declare class MemoryOidcStore implements OidcStore {
  constructor();
  saveRequest: OidcStore["saveRequest"];
  peekRequest: OidcStore["peekRequest"];
  takeRequest: OidcStore["takeRequest"];
  saveCode: OidcStore["saveCode"];
  consumeCode: OidcStore["consumeCode"];
  saveRefreshToken: OidcStore["saveRefreshToken"];
  getRefreshToken: OidcStore["getRefreshToken"];
  rotateRefreshToken: OidcStore["rotateRefreshToken"];
  deleteRefreshToken: OidcStore["deleteRefreshToken"];
  revokeFamily: OidcStore["revokeFamily"];
  getConsent: OidcStore["getConsent"];
  saveConsent: OidcStore["saveConsent"];
  revokeConsent: OidcStore["revokeConsent"];
}
/** Best-effort only: KV has no compare-and-swap. Prefer D1OidcStore or DoOidcStore. */
export declare class KvOidcStore extends MemoryOidcStore {
  constructor(kv: unknown, options?: { prefix?: string });
}
export declare class D1OidcStore extends MemoryOidcStore {
  constructor(db: unknown);
}
export declare class DoOidcStore extends MemoryOidcStore {
  constructor(binding: DurableObjectNamespaceLike, options?: { name?: string });
}

// ---- provider ----

export interface OidcEvent {
  type: string;
  client_id?: string;
  user_id?: string | number;
  [field: string]: unknown;
}

export interface OidcProviderConfig {
  auth: TelegramQrAuth;
  issuer: string;
  keys: SigningKey[];
  clients: ClientRegistry;
  store: OidcStore;
  pairwiseSalt?: string;
  basePath?: string;
  branding?: Record<string, string>;
  rateLimit?: (key: string, ctx: { request: Request }) => Promise<boolean> | boolean;
  onEvent?: (event: OidcEvent) => void;
  now?: () => number;
  accessTokenTtlSeconds?: number;
  idTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  codeTtlSeconds?: number;
  requestTtlSeconds?: number;
  requirePkce?: boolean;
  scopesSupported?: string[];
}

export interface OidcProvider {
  handle(request: Request): Promise<Response | null>;
  metadata(): Record<string, unknown>;
  jwks(): { keys: Jwk[] };
  paths: Record<"discovery" | "jwks" | "authorize" | "consent" | "token" | "userinfo" | "revoke", string>;
  keys: SigningKey[];
  verifyAccessToken(token: string): Promise<Record<string, any> | null>;
  verifyIdToken(token: string, clientId: string): Promise<Record<string, any> | null>;
  revokeConsent(userId: string | number, clientId: string): Promise<void>;
  auth: TelegramQrAuth;
  store: OidcStore;
  clients: ClientRegistry;
}

export declare function createOidcProvider(config: OidcProviderConfig): OidcProvider;

// ---- pages ----

export declare const SCOPE_DESCRIPTIONS: Record<string, string>;
export declare function renderConsentPage(params: {
  client: OidcClient;
  scopes: string[];
  session: { name: string; [field: string]: unknown };
  redirectUri?: string;
  requestId: string;
  csrfToken: string;
  actionPath: string;
  branding?: { accent?: string };
}): string;
export declare function renderErrorPage(error: string, description: string): string;
