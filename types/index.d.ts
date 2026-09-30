// Hand-written types. The package itself is plain ESM JavaScript with no build step — these exist
// so TypeScript consumers get completion and checking without the package needing a compiler.

export interface TelegramUser {
  id: number;
  first_name?: string;
  last_name?: string;
  username?: string;
}

export interface AuthUser {
  id: number;
  first_name: string;
  last_name: string;
  username: string;
}

export interface ClientContext {
  ip: string | null;
  userAgent: string | null;
  origin: string | null;
  at: string;
}

export interface LoginRecord {
  token: string;
  namespace: string;
  status: "pending" | "confirmed";
  user: AuthUser | null;
  createdAt: number;
  expiresAt: number;
  confirmedAt?: number | null;
  client?: ClientContext | null;
}

export interface LoginStore {
  create(record: { token: string; namespace: string; expiresAt: number; client?: ClientContext | null }): Promise<void>;
  get(token: string, namespace: string): Promise<LoginRecord | null>;
  /** Must return true only if the record was still pending, and must be atomic against itself. */
  confirm(token: string, namespace: string, user: AuthUser): Promise<boolean>;
  remove(token: string, namespace: string): Promise<void>;
  /** Optional housekeeping. KV expires records itself and has none. */
  sweep?(): Promise<void> | void;
}

export declare class MemoryLoginStore implements LoginStore {
  constructor();
  create(record: { token: string; namespace: string; expiresAt: number; client?: ClientContext | null }): Promise<void>;
  get(token: string, namespace: string): Promise<LoginRecord | null>;
  confirm(token: string, namespace: string, user: AuthUser): Promise<boolean>;
  remove(token: string, namespace: string): Promise<void>;
  sweep(): void;
}

export declare class D1LoginStore implements LoginStore {
  constructor(db: unknown, options?: { table?: string; sweepAfterSeconds?: number });
  create(record: { token: string; namespace: string; expiresAt: number; client?: ClientContext | null }): Promise<void>;
  get(token: string, namespace: string): Promise<LoginRecord | null>;
  confirm(token: string, namespace: string, user: AuthUser): Promise<boolean>;
  remove(token: string, namespace: string): Promise<void>;
  sweep(): Promise<void>;
}

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
  remove(token: string, namespace: string): Promise<void>;
  sweep(): Promise<void>;
}

/**
 * Builds the Durable Object class that backs DoLoginStore and DoOidcStore:
 * `export class QrAuthStorage extends defineQrAuthStorage(DurableObject) {}`.
 * `Base` is `DurableObject` from "cloudflare:workers".
 */
export declare function defineQrAuthStorage<T extends new (...args: any[]) => object>(Base: T): T;

export declare class KVLoginStore implements LoginStore {
  constructor(kv: unknown, options?: { prefix?: string });
  create(record: { token: string; namespace: string; expiresAt: number; client?: ClientContext | null }): Promise<void>;
  get(token: string, namespace: string): Promise<LoginRecord | null>;
  confirm(token: string, namespace: string, user: AuthUser): Promise<boolean>;
  remove(token: string, namespace: string): Promise<void>;
}

export interface TelegramApi {
  call(method: string, payload: unknown): Promise<any>;
  getChatMember?(chatId: string | number, userId: number): Promise<any>;
  sendMessage?(chatId: string | number, text: string, extra?: object): Promise<any>;
  deleteMessage?(chatId: string | number, messageId: number): Promise<any>;
}

export declare class TelegramClient implements TelegramApi {
  constructor(token: string, options?: { apiBase?: string; fetchImpl?: typeof fetch });
  call(method: string, payload: unknown): Promise<any>;
  getChatMember(chatId: string | number, userId: number): Promise<any>;
  sendMessage(chatId: string | number, text: string, extra?: object): Promise<any>;
  deleteMessage(chatId: string | number, messageId: number): Promise<any>;
}

/** "refresh" is passed only by the OIDC provider, on a refresh-token grant. */
export type GateStage = "confirm" | "poll" | "session" | "refresh";

export interface GateContext {
  telegram: TelegramApi | null;
  request?: Request;
  stage: GateStage;
}

/**
 * `transient: true` on a refusal means the gate could not decide (e.g. Telegram was unreachable) as
 * opposed to deciding "no". The built-in `chatMember` gate sets it on API errors; callers then
 * answer 503 / "try again" instead of clearing sessions or revoking refresh tokens.
 */
export type GateResult = boolean | { ok: boolean; reason?: string; transient?: boolean };
export type Gate = (user: { id: number; username?: string }, ctx: GateContext) => Promise<GateResult> | GateResult;

export declare function anyUser(): Gate;
export declare function chatMember(options: {
  chatId: string | number;
  statuses?: Set<string>;
  onError?: (err: unknown) => void;
}): Gate;
export declare function chatMemberOfAny(
  chatIds: string | Array<string | number>,
  options?: { statuses?: Set<string>; onError?: (err: unknown) => void }
): Gate;
export declare function chatMemberOfAll(
  chatIds: string | Array<string | number>,
  options?: { statuses?: Set<string>; onError?: (err: unknown) => void }
): Gate;
export declare function allowlist(ids: string | Array<string | number>): Gate;
export declare function denylist(ids: string | Array<string | number>): Gate;
export declare function every(...gates: Gate[]): Gate;
export declare function some(...gates: Gate[]): Gate;
export declare function parseIdList(ids: string | Array<string | number>): number[];
export declare function splitList(values: string | Array<string | number>): string[];
export declare function normalize(result: GateResult): { ok: boolean; reason?: string };

/** The same gate builders, grouped — `import { gates } from "telegram-qr-auth"`. */
export declare const gates: {
  anyUser: typeof anyUser;
  chatMember: typeof chatMember;
  chatMemberOfAny: typeof chatMemberOfAny;
  chatMemberOfAll: typeof chatMemberOfAll;
  allowlist: typeof allowlist;
  denylist: typeof denylist;
  every: typeof every;
  some: typeof some;
  normalize: typeof normalize;
  parseIdList: typeof parseIdList;
  splitList: typeof splitList;
};

export interface Branding {
  title?: string;
  heading?: string;
  subtitle?: string;
  waitingText?: string;
  successText?: string;
  expiredText?: string;
  deniedText?: string;
  retryText?: string;
  /** Text of the "Open Telegram" button shown to touch devices. */
  mobileLinkText?: string;
  /** Subtitle shown to touch devices instead of `subtitle`. */
  mobileSubtitle?: string;
  /** Hint under the QR on pointer devices. */
  qrHintText?: string;
  /** Tooltip and accessible name of the (always clickable) QR. */
  qrLinkTitle?: string;
  accent?: string;
  gradientFrom?: string;
  gradientTo?: string;
  qrDark?: string;
  qrLight?: string;
  logoHtml?: string;
  footerHtml?: string;
  headHtml?: string;
  botSuccessText?: string;
  botBadTokenText?: string;
  botExpiredText?: string;
  botDeniedText?: string;
}

export interface QrOptions {
  cellSize?: number;
  margin?: number;
  dark?: string;
  light?: string;
  errorCorrection?: "L" | "M" | "Q" | "H";
  label?: string;
}

export interface SessionOptions {
  secret?: string;
  cookieName?: string;
  maxAgeSeconds?: number;
  keyLabel?: string;
  sameSite?: "Strict" | "Lax" | "None";
  secure?: boolean;
  path?: string;
  domain?: string;
}

export interface SessionCodec {
  cookieName: string;
  maxAgeSeconds: number;
  sign(claims: object, ttlSeconds?: number): Promise<string>;
  verify(cookieValue: string | null): Promise<Record<string, any> | null>;
  cookieHeader(value: string, maxAge?: number): string;
  clearCookieHeader(): string;
  read(request: Request): string | null;
}

export declare function createSessionCodec(options: SessionOptions & { secret: string }): SessionCodec;
export declare function parseCookies(header: string | null): Record<string, string>;
export declare const DEFAULT_MAX_AGE_SECONDS: number;

export interface TelegramQrAuthConfig {
  botToken?: string;
  botUsername: string;
  store: LoginStore;
  namespace?: string;
  authorize?: Gate;
  telegram?: TelegramApi;
  session?: SessionOptions;
  tokenTtlSeconds?: number;
  tokenBytes?: number;
  basePath?: string;
  redirectTo?: string;
  pollIntervalMs?: number;
  branding?: Branding;
  qr?: QrOptions;
  renderLoginPage?: (params: RenderLoginPageParams) => string;
  claims?: (user: AuthUser) => Record<string, unknown>;
  captureClient?: boolean;
  allowAssertions?: boolean;
  now?: () => number;
}

export interface RenderLoginPageParams {
  token: string;
  deepLink: string;
  qrSvg: string;
  error?: string;
  pollPath: string;
  pollIntervalMs?: number;
  branding?: Branding;
  redirectTo?: string;
}

export interface SessionClaims extends Record<string, unknown> {
  id: number;
  name: string;
  username?: string;
  exp: number;
}

export interface BeginLoginResult {
  token: string;
  deepLink: string;
  payload: string;
  svg: string;
  expiresIn: number;
}

export interface ConfirmResult {
  ok: boolean;
  reason: string | null;
  user: AuthUser | null;
  client?: ClientContext | null;
}

export type GuardResult =
  | { ok: true; session: SessionClaims }
  | { ok: false; reason: string; response: Response };

export interface TelegramQrAuth {
  namespace: string;
  basePath: string;
  paths: { poll: string; login: string; logout: string; qr: string };
  cookieName: string;
  tokenTtlSeconds: number;

  beginLogin(options?: { request?: Request }): Promise<BeginLoginResult>;
  parseStartPayload(input: string): string | null;
  confirm(args: { token: string; user: TelegramUser }): Promise<ConfirmResult>;
  handleStart(args: { text: string; from: TelegramUser }): Promise<
    ({ matched: false } | ({ matched: true; replyText: string } & ConfirmResult))
  >;
  poll(request: Request): Promise<Response>;
  getSession(request: Request): Promise<SessionClaims | null>;
  verifyAssertion(assertion: string | null): Promise<SessionClaims | null>;
  guard(request: Request, options?: { onDenied?: (session: SessionClaims, reason: string) => Promise<Response | undefined> | Response | undefined }): Promise<GuardResult>;
  loginPage(options?: { error?: string; request?: Request; redirectTo?: string }): Promise<string>;
  loginResponse(options?: { error?: string; status?: number; request?: Request; clearCookie?: boolean; redirectTo?: string }): Promise<Response>;
  logoutResponse(options?: { redirectTo?: string }): Response;
  handle(request: Request): Promise<Response | null>;
  deepLinkFor(token: string): string;

  store: LoginStore;
  telegram: TelegramApi | null;
  session: SessionCodec;
  authorize: Gate;
}

export declare function createTelegramQrAuth(config: TelegramQrAuthConfig): TelegramQrAuth;
export declare const POLL_STATUSES: readonly string[];
export declare function jsonResponse(data: unknown, status?: number, extraHeaders?: Headers): Response;

export interface StartHandlerOptions {
  telegram?: TelegramApi;
  deleteCommandMessage?: boolean;
  showClientContext?: boolean;
  onSignIn?: (user: AuthUser, result: ConfirmResult) => void | Promise<void>;
}

export declare function createStartHandler(auth: TelegramQrAuth, options?: StartHandlerOptions): (update: any) => Promise<boolean>;
export declare function createWebhookHandler(
  auth: TelegramQrAuth,
  options?: StartHandlerOptions & { secretToken?: string; onUnhandled?: (update: any) => void | Promise<void> }
): (request: Request) => Promise<Response>;

export declare function qrSvg(text: string, options?: QrOptions): string;
export declare function qrDataUri(text: string, options?: QrOptions): string;
export declare function renderLoginPage(params: RenderLoginPageParams): string;
export declare const DEFAULT_BRANDING: Required<Branding>;
export declare function escapeHtml(text: unknown): string;

export declare function displayName(user: TelegramUser | null | undefined): string;
export declare function toAuthUser(user: TelegramUser): AuthUser;
export declare function isChatMember(
  telegram: TelegramApi,
  chatId: string | number,
  userId: number,
  options?: { statuses?: Set<string>; onError?: (err: unknown) => void }
): Promise<boolean>;
export declare const MEMBER_STATUSES: Set<string>;

export declare function hmacSha256(keyBytes: Uint8Array, message: string): Promise<Uint8Array>;
export declare function toHex(bytes: Uint8Array | number[]): string;
export declare function timingSafeEqualHex(a: string, b: string): boolean;
export declare function base64UrlEncode(bytes: Uint8Array): string;
export declare function base64UrlDecode(str: string): Uint8Array;
export declare function randomToken(byteLength?: number): string;
export declare function tokenPattern(byteLength?: number): RegExp;
