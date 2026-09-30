// Types for telegram-qr-auth/do — Durable Object storage for login records and the OIDC provider.

import type { LoginStore, LoginRecord, AuthUser, ClientContext } from "./index";
import type { OidcStore } from "./oidc";

/** Durable Object namespace binding, e.g. `env.QRAUTH_DO`. */
export interface DurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): unknown;
}

/** Login records in a SQLite-backed Durable Object built with `defineQrAuthStorage`. */
export declare class DoLoginStore implements LoginStore {
  constructor(binding: DurableObjectNamespaceLike, options?: { name?: string });
  create(record: { token: string; namespace: string; expiresAt: number; client?: ClientContext | null }): Promise<void>;
  get(token: string, namespace: string): Promise<LoginRecord | null>;
  confirm(token: string, namespace: string, user: AuthUser): Promise<boolean>;
  consume(token: string, namespace: string): Promise<LoginRecord | null>;
  remove(token: string, namespace: string): Promise<void>;
  sweep(): Promise<void>;
}

/**
 * Builds the Durable Object class that backs DoLoginStore and DoOidcStore:
 * `export class QrAuthStorage extends defineQrAuthStorage(DurableObject) {}`.
 * `Base` is `DurableObject` from "cloudflare:workers".
 */
export declare function defineQrAuthStorage<T extends new (...args: any[]) => object>(Base: T): T;

/** OIDC provider state in a Durable Object built with `defineQrAuthStorage`. */
export declare class DoOidcStore implements OidcStore {
  constructor(binding: DurableObjectNamespaceLike, options?: { name?: string });
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
