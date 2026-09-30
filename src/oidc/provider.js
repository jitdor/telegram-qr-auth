// An OpenID Connect provider with Telegram QR as the authentication method.
//
// The base package answers "who is this person?" with a QR scan. This turns that answer into
// something a third party can safely consume: standard OIDC, ES256-signed tokens, a published
// JWKS, per-client audiences, consent, and revocable refresh tokens. A relying party integrates
// with a stock OIDC library and never learns anything about Telegram.
//
// The endpoint map:
//
//   GET  /.well-known/openid-configuration   discovery
//   GET  /.well-known/jwks.json              public keys
//   GET  /authorize                          starts a flow; shows the QR, then consent
//   POST /consent                            the user's decision
//   POST /token                              code -> tokens, and refresh rotation
//   GET  /userinfo                           claims for an access token
//   POST /revoke                             refresh token revocation
//
// Plus the base package's own /auth/* routes, which is where the QR actually lives.
//
// Two invariants worth stating outright, because everything else follows from them:
//
//   1. Until `client_id` and `redirect_uri` are both validated, NOTHING is redirected anywhere.
//      Errors before that point render a page. Redirecting an unvalidated redirect_uri is how you
//      hand an attacker an authorization code.
//   2. Authorization codes and refresh tokens are single-use, and reusing one is treated as theft,
//      not as a retry.

import { randomToken } from "../crypto.js";
import { signJwt, verifyJwt } from "./jwt.js";
import { toJwks } from "./keys.js";
import { matchRedirectUri, verifyClientSecret, subjectFor, CONFIDENTIAL_CLIENT } from "./clients.js";
import { verifyChallenge, isValidChallenge, S256 } from "./pkce.js";
import { renderConsentPage, renderErrorPage } from "./consent-page.js";
import { normalize as normalizeGate } from "../gates.js";

const DEFAULTS = {
  accessTokenTtlSeconds: 3600, // 1 hour
  idTokenTtlSeconds: 3600,
  refreshTokenTtlSeconds: 30 * 24 * 3600, // 30 days
  codeTtlSeconds: 60,
  requestTtlSeconds: 15 * 60,
  requirePkce: true,
  scopesSupported: ["openid", "profile", "offline_access"],
};

/**
 * @param {object} config
 * @param {object} config.auth        A createTelegramQrAuth() instance — the authentication half.
 *                                    Configure it with
 *                                    `claims: () => ({ auth_time: Math.floor(Date.now()/1000) })`
 *                                    so `max_age` and `prompt=login` can work.
 * @param {string} config.issuer      This provider's origin, e.g. "https://auth.example.com".
 *                                    Must match exactly what relying parties configure.
 * @param {Array}  config.keys        From loadSigningKeys(). First one signs; all are published.
 * @param {object} config.clients     A client registry (see ./clients.js).
 * @param {object} config.store       An OIDC store (see ./store.js).
 * @param {string} [config.pairwiseSalt]  Required if any client sets `pairwise: true`.
 * @param {string} [config.basePath="/"]
 * @param {object} [config.branding]
 * @param {Function} [config.rateLimit]  `async (key, ctx) => boolean` — false to reject. Wire this
 *                                    to your platform's limiter before opening to third parties;
 *                                    /token and /authorize are unauthenticated by definition.
 * @param {Function} [config.onEvent] `(event) => void` audit hook. Every issuance, denial and
 *                                    reuse detection passes through it.
 */
export function createOidcProvider(config) {
  const {
    auth,
    issuer,
    keys,
    clients,
    store,
    pairwiseSalt,
    basePath = "/",
    branding = {},
    rateLimit,
    onEvent = () => {},
    now = () => Math.floor(Date.now() / 1000),
  } = config;

  if (!auth) throw new Error("createOidcProvider: `auth` (a telegram-qr-auth instance) is required");
  if (!issuer) throw new Error("createOidcProvider: `issuer` is required");
  if (!Array.isArray(keys) || !keys.length) throw new Error("createOidcProvider: `keys` is required (see loadSigningKeys)");
  if (!clients) throw new Error("createOidcProvider: `clients` registry is required");
  if (!store) throw new Error("createOidcProvider: `store` is required");
  if (issuer.endsWith("/")) throw new Error("createOidcProvider: `issuer` must not end with a slash");

  const options = { ...DEFAULTS, ...config };
  const signingKey = keys[0];

  const paths = {
    discovery: "/.well-known/openid-configuration",
    jwks: "/.well-known/jwks.json",
    authorize: join(basePath, "authorize"),
    consent: join(basePath, "consent"),
    token: join(basePath, "token"),
    userinfo: join(basePath, "userinfo"),
    revoke: join(basePath, "revoke"),
  };

  // ---------------------------------------------------------------------------------------------
  // Discovery
  // ---------------------------------------------------------------------------------------------

  function metadata() {
    return {
      issuer,
      authorization_endpoint: issuer + paths.authorize,
      token_endpoint: issuer + paths.token,
      userinfo_endpoint: issuer + paths.userinfo,
      jwks_uri: issuer + paths.jwks,
      revocation_endpoint: issuer + paths.revoke,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public", "pairwise"],
      id_token_signing_alg_values_supported: ["ES256"],
      scopes_supported: options.scopesSupported,
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
      code_challenge_methods_supported: [S256], // no "plain": see ./pkce.js
      claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username"],
      // Implicit and hybrid are absent on purpose: both put tokens in a URL fragment, and neither
      // has a reason to exist now that code+PKCE works in a browser.
    };
  }

  // ---------------------------------------------------------------------------------------------
  // /authorize
  // ---------------------------------------------------------------------------------------------

  async function handleAuthorize(request) {
    const url = new URL(request.url);

    // A paused request resuming after the QR sign-in or a consent decision.
    const resumeId = url.searchParams.get("request_id");
    let params;
    let requestId;

    if (resumeId) {
      const saved = await store.peekRequest(resumeId);
      if (!saved) {
        return errorPage("invalid_request", "This sign-in took too long. Start again from the app.");
      }
      params = saved.params;
      requestId = resumeId;
    } else {
      params = Object.fromEntries(url.searchParams);
      requestId = randomToken(16);
    }

    if (rateLimit && !(await rateLimit(`authorize:${params.client_id ?? "anonymous"}`, { request }))) {
      return errorPage("temporarily_unavailable", "Too many sign-in attempts. Try again shortly.");
    }

    // ---- Phase 1: nothing may be redirected until these two pass ----

    const client = params.client_id ? await clients.get(params.client_id) : null;
    if (!client) {
      onEvent({ type: "authorize.unknown_client", client_id: params.client_id });
      return errorPage("invalid_client", "That application is not registered with us.");
    }

    const redirectUri = matchRedirectUri(client, params.redirect_uri);
    if (!redirectUri) {
      // Deliberately NOT redirected. If we bounced back to an unregistered URI we would be the
      // open redirect that leaks the next client's codes.
      onEvent({ type: "authorize.bad_redirect_uri", client_id: client.client_id, redirect_uri: params.redirect_uri });
      return errorPage(
        "invalid_request",
        "That application asked us to return you somewhere it has not registered. Nothing was shared."
      );
    }

    // ---- Phase 2: errors now go back to the client, per OAuth ----

    const fail = (error, description) => redirectError(redirectUri, error, description, params.state);

    if (params.response_type !== "code") {
      return fail("unsupported_response_type", "Only the authorization code flow is supported.");
    }

    if (params.response_mode !== undefined && params.response_mode !== "query") {
      return fail("invalid_request", "Only response_mode=query is supported.");
    }
    for (const name of ["state", "nonce"]) {
      if (params[name] !== undefined && String(params[name]).length > MAX_ECHOED_LENGTH) {
        return fail("invalid_request", `${name} is too long.`);
      }
    }

    const scopes = String(params.scope ?? "").split(/\s+/).filter(Boolean);
    if (!scopes.includes("openid")) return fail("invalid_scope", "The openid scope is required.");
    const allowed = new Set(client.scopes);
    const unknown = scopes.filter((scope) => !allowed.has(scope));
    if (unknown.length) return fail("invalid_scope", `Not permitted for this client: ${unknown.join(", ")}`);

    const pkceRequired = options.requirePkce || client.type !== CONFIDENTIAL_CLIENT;
    if (pkceRequired || params.code_challenge) {
      if (!isValidChallenge(params.code_challenge)) {
        return fail("invalid_request", "A valid S256 code_challenge is required.");
      }
      if ((params.code_challenge_method ?? S256) !== S256) {
        return fail("invalid_request", "Only the S256 code_challenge_method is supported.");
      }
    }

    const prompt = new Set(String(params.prompt ?? "").split(/\s+/).filter(Boolean));

    // ---- Phase 3: authenticate the human ----

    let session = await auth.getSession(request);

    if (session && (prompt.has("login") || exceedsMaxAge(session, params.max_age, now()))) {
      session = null; // re-authentication demanded by the client
    }

    if (!session) {
      if (prompt.has("none")) return fail("login_required", "The user is not signed in.");

      // Park the request and send them to the QR. The login page will bring them back here.
      await store.saveRequest(requestId, { params: { ...params, redirect_uri: redirectUri }, createdAt: now() }, options.requestTtlSeconds);
      return auth.loginResponse({
        request,
        redirectTo: `${paths.authorize}?request_id=${encodeURIComponent(requestId)}`,
      });
    }

    // The live authorization gate — group membership, allowlist, whatever the deployment uses.
    // Runs on every authorize, so someone removed from the group cannot mint new tokens even with
    // a valid provider session.
    const gate = normalizeGate(
      await auth.authorize({ id: session.id, username: session.username }, { telegram: auth.telegram, request, stage: "session" })
    );
    if (!gate.ok) {
      onEvent({ type: "authorize.denied", user_id: session.id, client_id: client.client_id, reason: gate.reason });
      return fail("access_denied", "You are not permitted to sign in to this provider.");
    }

    // Per-client gate, if the client registered one.
    if (client.authorize) {
      const clientGate = normalizeGate(await client.authorize({ id: session.id, username: session.username }, { request, client }));
      if (!clientGate.ok) return fail("access_denied", "You are not permitted to use this application.");
    }

    // ---- Phase 4: consent ----

    // prompt=consent asks to be shown the screen again, even for a grant already remembered. It
    // cannot force a first-party client (which has no consent screen) to show one.
    const needsConsent =
      !client.first_party && (prompt.has("consent") || !(await hasConsent(session.id, client.client_id, scopes)));
    if (needsConsent) {
      if (prompt.has("none")) return fail("consent_required", "Consent is required.");

      const csrfToken = randomToken(16);
      await store.saveRequest(
        requestId,
        { params: { ...params, redirect_uri: redirectUri }, userId: session.id, csrfToken, createdAt: now() },
        options.requestTtlSeconds
      );

      return html(
        renderConsentPage({
          client,
          scopes,
          session,
          redirectUri,
          requestId,
          csrfToken,
          actionPath: paths.consent,
          branding,
        })
      );
    }

    // ---- Phase 5: issue the code ----

    if (resumeId) await store.takeRequest(resumeId); // done with the parked request
    return issueCode({ client, redirectUri, scopes, session, params });
  }

  /** POST from the consent form. */
  async function handleConsent(request) {
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });

    let form;
    try {
      form = await request.formData();
    } catch {
      return errorPage("invalid_request", "That form could not be read. Start again from the app.");
    }
    const requestId = String(form.get("request_id") ?? "");
    const csrf = String(form.get("csrf") ?? "");
    const decision = String(form.get("decision") ?? "");

    const saved = await store.peekRequest(requestId);
    if (!saved) return errorPage("invalid_request", "This sign-in expired. Start again from the app.");

    // Three checks, all necessary: the form must carry the token we generated (CSRF), and the
    // person submitting it must be the same signed-in user we rendered it for — otherwise one user
    // could approve a grant that lands in another's account.
    const session = await auth.getSession(request);
    if (!session) return errorPage("login_required", "Your session ended. Start again from the app.");
    if (!saved.csrfToken || saved.csrfToken !== csrf) {
      return errorPage("invalid_request", "That form could not be verified. Start again from the app.");
    }
    if (String(saved.userId) !== String(session.id)) {
      return errorPage("invalid_request", "That request belongs to a different sign-in.");
    }

    const client = await clients.get(saved.params.client_id);
    if (!client) return errorPage("invalid_client", "That application is no longer registered.");
    const redirectUri = matchRedirectUri(client, saved.params.redirect_uri);
    if (!redirectUri) return errorPage("invalid_request", "That application's callback is no longer registered.");

    await store.takeRequest(requestId);
    const scopes = String(saved.params.scope ?? "").split(/\s+/).filter(Boolean);

    if (decision !== "allow") {
      onEvent({ type: "consent.denied", user_id: session.id, client_id: client.client_id });
      return redirectError(redirectUri, "access_denied", "The user declined.", saved.params.state);
    }

    await store.saveConsent(session.id, client.client_id, scopes);
    onEvent({ type: "consent.granted", user_id: session.id, client_id: client.client_id, scopes });

    return issueCode({ client, redirectUri, scopes, session, params: saved.params });
  }

  async function hasConsent(userId, clientId, scopes) {
    const consent = await store.getConsent(userId, clientId);
    if (!consent) return false;
    const granted = new Set(consent.scopes ?? []);
    // A previously granted consent covers a *subset* only. Asking for more re-prompts, which is
    // what stops a client quietly widening its access after the fact.
    return scopes.every((scope) => granted.has(scope));
  }

  async function issueCode({ client, redirectUri, scopes, session, params }) {
    const code = randomToken(32);
    await store.saveCode(
      code,
      {
        clientId: client.client_id,
        redirectUri,
        scopes,
        userId: session.id,
        profile: { name: session.name, preferred_username: session.username ?? null },
        nonce: params.nonce ?? null,
        codeChallenge: params.code_challenge ?? null,
        authTime: session.auth_time ?? null,
      },
      options.codeTtlSeconds
    );

    onEvent({ type: "code.issued", user_id: session.id, client_id: client.client_id, scopes });

    const location = new URL(redirectUri);
    location.searchParams.set("code", code);
    if (params.state !== undefined && params.state !== null) location.searchParams.set("state", params.state);
    return redirect(location.toString());
  }

  // ---------------------------------------------------------------------------------------------
  // /token
  // ---------------------------------------------------------------------------------------------

  async function handleToken(request) {
    if (request.method !== "POST") return tokenError("invalid_request", "POST required", 405);

    let form;
    try {
      form = await request.formData();
    } catch {
      return tokenError("invalid_request", "Expected application/x-www-form-urlencoded");
    }
    const body = Object.fromEntries([...form.entries()].map(([k, v]) => [k, String(v)]));

    const authenticated = await authenticateClient(request, body);
    if (!authenticated.ok) return authenticated.response;
    const client = authenticated.client;

    if (rateLimit && !(await rateLimit(`token:${client.client_id}`, { request }))) {
      return tokenError("temporarily_unavailable", "Rate limited", 429);
    }

    switch (body.grant_type) {
      case "authorization_code":
        return grantAuthorizationCode(client, body);
      case "refresh_token":
        return grantRefreshToken(client, body, request);
      default:
        return tokenError("unsupported_grant_type", "Supported: authorization_code, refresh_token");
    }
  }

  /**
   * Client authentication. Confidential clients present a secret (Basic preferred); public clients
   * present only a client_id and lean entirely on PKCE.
   */
  async function authenticateClient(request, body) {
    let clientId = body.client_id;
    let clientSecret = body.client_secret;

    const header = request.headers.get("Authorization");
    if (header?.startsWith("Basic ")) {
      try {
        const decoded = atob(header.slice(6));
        const separator = decoded.indexOf(":");
        if (separator === -1) throw new Error("malformed");
        // RFC 6749 form-encodes both halves before base64.
        clientId = decodeURIComponent(decoded.slice(0, separator));
        clientSecret = decodeURIComponent(decoded.slice(separator + 1));
      } catch {
        return { ok: false, response: tokenError("invalid_client", "Malformed Basic credentials", 401) };
      }
    }

    if (!clientId) return { ok: false, response: tokenError("invalid_client", "client_id is required", 401) };

    const client = await clients.get(clientId);
    // Same error for unknown client and wrong secret, so this endpoint cannot be used to enumerate
    // which client ids exist.
    if (!client) return { ok: false, response: tokenError("invalid_client", "Client authentication failed", 401) };

    if (client.type === CONFIDENTIAL_CLIENT) {
      if (!(await verifyClientSecret(client, clientSecret))) {
        onEvent({ type: "token.bad_client_secret", client_id: clientId });
        return { ok: false, response: tokenError("invalid_client", "Client authentication failed", 401) };
      }
    } else if (clientSecret) {
      return { ok: false, response: tokenError("invalid_client", "This client must not send a secret", 401) };
    }

    return { ok: true, client };
  }

  async function grantAuthorizationCode(client, body) {
    if (!body.code) return tokenError("invalid_request", "code is required");

    const payload = await store.consumeCode(body.code);
    if (!payload) {
      onEvent({ type: "token.bad_code", client_id: client.client_id });
      return tokenError("invalid_grant", CODE_REJECTED);
    }

    // A code issued to one client being redeemed by another is theft, not confusion.
    if (payload.clientId !== client.client_id) {
      onEvent({ type: "token.code_client_mismatch", client_id: client.client_id, issued_to: payload.clientId });
      return tokenError("invalid_grant", CODE_REJECTED);
    }

    // redirect_uri must be repeated and must match — this is what stops a code obtained via one
    // registered callback from being redeemed as though it came through another.
    if (body.redirect_uri !== payload.redirectUri) {
      return tokenError("invalid_grant", CODE_REJECTED);
    }

    if (payload.codeChallenge) {
      if (!(await verifyChallenge(body.code_verifier, payload.codeChallenge))) {
        onEvent({ type: "token.pkce_failed", client_id: client.client_id });
        return tokenError("invalid_grant", CODE_REJECTED);
      }
    } else if (options.requirePkce || client.type !== CONFIDENTIAL_CLIENT) {
      return tokenError("invalid_grant", CODE_REJECTED);
    }

    return issueTokens({
      client,
      userId: payload.userId,
      profile: payload.profile,
      scopes: payload.scopes,
      nonce: payload.nonce,
      authTime: payload.authTime,
      familyId: randomToken(16),
    });
  }

  async function grantRefreshToken(client, body, request) {
    if (!body.refresh_token) return tokenError("invalid_request", "refresh_token is required");

    const payload = await store.getRefreshToken(body.refresh_token);
    if (!payload) return tokenError("invalid_grant", "That refresh token is invalid or expired");
    if (payload.clientId !== client.client_id) {
      return tokenError("invalid_grant", "That refresh token was not issued to this client");
    }

    // Rotation with reuse detection. A token presented twice means either a client retry or a
    // stolen token already spent by its thief — and we cannot tell which from here. Killing the
    // whole family is the safe resolution: the attacker loses access, and the user re-authenticates.
    const reuse = async () => {
      onEvent({ type: "token.refresh_reuse", client_id: client.client_id, user_id: payload.userId, family: payload.familyId });
      await store.revokeFamily(payload.familyId);
      return tokenError("invalid_grant", "That refresh token has already been used");
    };
    if (payload.used) return reuse();

    // Refresh is a side door next to /authorize, so it faces the same checks. Without them, someone
    // removed from the group would keep minting tokens until the refresh TTL ran out.
    const user = { id: payload.userId, username: payload.profile?.preferred_username ?? undefined };
    let clientGate;
    try {
      const gate = normalizeGate(await auth.authorize(user, { telegram: auth.telegram, request, stage: "refresh" }));
      clientGate = gate.ok && client.authorize ? normalizeGate(await client.authorize(user, { request, client })) : gate;
    } catch {
      // Cannot tell (Telegram unreachable, say). Fail closed, but do not burn the token or the
      // family: the client can retry the same refresh token once the gate answers again.
      return tokenError("temporarily_unavailable", "Could not verify access right now. Try again shortly.", 503);
    }
    if (!clientGate.ok) {
      onEvent({ type: "token.refresh_denied", client_id: client.client_id, user_id: payload.userId, reason: clientGate.reason });
      await store.revokeFamily(payload.familyId);
      return tokenError("invalid_grant", "Access for this user has been revoked");
    }

    // Consent withdrawn between issuance and refresh must end the grant.
    if (!client.first_party && !(await hasConsent(payload.userId, client.client_id, payload.scopes))) {
      await store.revokeFamily(payload.familyId);
      return tokenError("invalid_grant", "Consent for this application has been withdrawn");
    }

    // The spend itself is one atomic store operation. Reading `used`, awaiting the checks above and
    // then writing `used: true` would let two simultaneous requests both win.
    const rotation = await store.rotateRefreshToken(body.refresh_token);
    if (rotation.status === "reused") return reuse();
    if (rotation.status !== "ok") return tokenError("invalid_grant", "That refresh token is invalid or expired");

    const requested = String(body.scope ?? "").split(/\s+/).filter(Boolean);
    // Scope may narrow on refresh, never widen.
    const scopes = requested.length ? requested.filter((scope) => payload.scopes.includes(scope)) : payload.scopes;

    return issueTokens({
      client,
      userId: payload.userId,
      profile: payload.profile,
      scopes,
      nonce: null, // nonce belongs to the original authentication, never to a refresh
      authTime: payload.authTime,
      familyId: payload.familyId,
    });
  }

  async function issueTokens({ client, userId, profile, scopes, nonce, authTime, familyId }) {
    const issuedAt = now();
    const sub = await subjectFor(client, userId, pairwiseSalt);

    const accessToken = await signJwt(
      {
        iss: issuer,
        sub,
        aud: issuer, // the userinfo endpoint is the only resource server here
        client_id: client.client_id,
        scope: scopes.join(" "),
        iat: issuedAt,
        exp: issuedAt + options.accessTokenTtlSeconds,
        jti: randomToken(16),
        // Profile claims ride along so /userinfo needs no storage of its own. They are a snapshot
        // from sign-in time, not a live read of Telegram — which is exactly what OIDC expects, and
        // why an access token's lifetime should be short.
        ...(scopes.includes("profile") ? profileClaims(profile) : {}),
      },
      signingKey,
      "at+jwt"
    );

    const idToken = await signJwt(
      {
        iss: issuer,
        sub,
        aud: client.client_id,
        iat: issuedAt,
        exp: issuedAt + options.idTokenTtlSeconds,
        ...(authTime ? { auth_time: authTime } : {}),
        ...(nonce ? { nonce } : {}),
        ...(scopes.includes("profile") ? profileClaims(profile) : {}),
      },
      signingKey,
      "JWT"
    );

    const response = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: options.accessTokenTtlSeconds,
      id_token: idToken,
      scope: scopes.join(" "),
    };

    if (scopes.includes("offline_access")) {
      const refreshToken = randomToken(32);
      await store.saveRefreshToken(
        refreshToken,
        { clientId: client.client_id, userId, profile, scopes, familyId, authTime, used: false },
        options.refreshTokenTtlSeconds
      );
      response.refresh_token = refreshToken;
    }

    onEvent({ type: "token.issued", user_id: userId, client_id: client.client_id, scopes });
    return json(response);
  }

  function profileClaims(profile) {
    return {
      name: profile?.name ?? undefined,
      preferred_username: profile?.preferred_username ?? undefined,
    };
  }

  // ---------------------------------------------------------------------------------------------
  // /userinfo and /revoke
  // ---------------------------------------------------------------------------------------------

  async function handleUserinfo(request) {
    const header = request.headers.get("Authorization") ?? "";
    if (!header.toLowerCase().startsWith("bearer ")) {
      // RFC 6750 says say so in the header, not just the body.
      return new Response(JSON.stringify({ error: "invalid_token" }), {
        status: 401,
        headers: { "Content-Type": "application/json", "WWW-Authenticate": 'Bearer realm="userinfo"', "Cache-Control": "no-store" },
      });
    }

    const claims = await verifyJwt(header.slice(7).trim(), {
      keys,
      issuer,
      audience: issuer,
      typ: "at+jwt", // an id_token presented here must be refused: different audience, different purpose
      now,
    });
    if (!claims || !String(claims.scope ?? "").split(" ").includes("openid")) {
      return new Response(JSON.stringify({ error: "invalid_token" }), {
        status: 401,
        headers: { "Content-Type": "application/json", "WWW-Authenticate": 'Bearer error="invalid_token"', "Cache-Control": "no-store" },
      });
    }

    return json({
      sub: claims.sub,
      ...(claims.name ? { name: claims.name } : {}),
      ...(claims.preferred_username ? { preferred_username: claims.preferred_username } : {}),
    });
  }

  async function handleRevoke(request) {
    if (request.method !== "POST") return tokenError("invalid_request", "POST required", 405);

    let form;
    try {
      form = await request.formData();
    } catch {
      return tokenError("invalid_request", "Expected application/x-www-form-urlencoded");
    }
    const body = Object.fromEntries([...form.entries()].map(([k, v]) => [k, String(v)]));

    const authenticated = await authenticateClient(request, body);
    if (!authenticated.ok) return authenticated.response;

    const token = body.token;
    if (token) {
      const payload = await store.getRefreshToken(token);
      // Only the client the token belongs to may revoke it. RFC 7009 says respond 200 regardless,
      // so a caller cannot probe which tokens exist.
      if (payload && payload.clientId === authenticated.client.client_id) {
        await store.revokeFamily(payload.familyId);
        onEvent({ type: "token.revoked", client_id: payload.clientId, user_id: payload.userId });
      }
    }

    return new Response(null, { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  // ---------------------------------------------------------------------------------------------

  /** Routes every OIDC endpoint. Returns null for paths it does not own. */
  async function handle(request) {
    const url = new URL(request.url);

    switch (url.pathname) {
      case paths.discovery:
        return json(metadata(), 200, { "Cache-Control": "public, max-age=3600" });
      case paths.jwks:
        // Cacheable, and must be: relying parties fetch it constantly. Rotation is why the max-age
        // is an hour rather than a day — a new key needs to become visible before it signs.
        return json(toJwks(keys), 200, { "Cache-Control": "public, max-age=3600" });
      case paths.authorize:
        return handleAuthorize(request);
      case paths.consent:
        return handleConsent(request);
      case paths.token:
        return handleToken(request);
      case paths.userinfo:
        return handleUserinfo(request);
      case paths.revoke:
        return handleRevoke(request);
      default:
        // Not ours — let the base package's /auth/* routes have a look.
        return auth.handle(request);
    }
  }

  return {
    handle,
    metadata,
    jwks: () => toJwks(keys),
    paths,
    keys,
    /** Verifies an access token this provider issued — for a resource server in the same runtime. */
    verifyAccessToken: (token) => verifyJwt(token, { keys, issuer, audience: issuer, typ: "at+jwt", now }),
    /** Verifies an id token as a specific client would. */
    verifyIdToken: (token, clientId) => verifyJwt(token, { keys, issuer, audience: clientId, typ: "JWT", now }),
    revokeConsent: (userId, clientId) => store.revokeConsent(userId, clientId),
    auth,
    store,
    clients,
  };
}

// -------------------------------------------------------------------------------------------------

// One description for every way a code can fail, so /token is not an oracle for which check tripped
// (valid code? right client? right verifier?). The distinctions go to onEvent instead.
const CODE_REJECTED = "The authorization code is invalid, expired, or does not match this request";

// Bounds for values we echo into redirect URLs and sign into JWTs.
const MAX_ECHOED_LENGTH = 512;

function exceedsMaxAge(session, maxAge, seconds) {
  if (maxAge === undefined || maxAge === null || maxAge === "") return false;
  const limit = Number(maxAge);
  if (!Number.isFinite(limit)) return false;
  // No auth_time means we cannot prove the session is fresh enough, so re-authenticate rather than
  // assume. Configure the base provider's `claims` hook to supply it.
  if (!session.auth_time) return true;
  return seconds - session.auth_time > limit;
}

function redirectError(redirectUri, error, description, state) {
  const location = new URL(redirectUri);
  location.searchParams.set("error", error);
  if (description) location.searchParams.set("error_description", description);
  if (state !== undefined && state !== null) location.searchParams.set("state", state);
  return redirect(location.toString());
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { Location: location, "Cache-Control": "no-store" } });
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extraHeaders },
  });
}

function tokenError(error, description, status = 400) {
  const headers = { "Content-Type": "application/json", "Cache-Control": "no-store" };
  if (status === 401) headers["WWW-Authenticate"] = 'Basic realm="token"';
  return new Response(JSON.stringify({ error, error_description: description }), { status, headers });
}

function errorPage(error, description) {
  return new Response(renderErrorPage(error, description), {
    // On this HTML path "temporarily_unavailable" only ever means the rate limiter said no, hence
    // 429. The /token endpoint's 503 for the same code (refresh gate unreachable) is a different
    // condition: the service could not answer, rather than the caller asking too often.
    status: error === "temporarily_unavailable" ? 429 : 400,
    headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" },
  });
}

function join(base, segment) {
  const trimmed = base.endsWith("/") ? base.slice(0, -1) : base;
  return `${trimmed}/${segment}`;
}
