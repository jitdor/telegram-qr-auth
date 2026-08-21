// The client registry.
//
// `redirect_uri` validation is the single most security-critical function in an OIDC provider. A
// provider that redirects to an attacker-chosen URI hands them an authorization code for whoever
// just signed in — every published "OAuth open redirect" incident is some variation of this. So:
// exact string match against a pre-registered list, no prefix matching, no wildcards, no
// normalisation cleverness. If a client needs three callback URLs, it registers three.

import { timingSafeEqualHex, toHex, hmacSha256 } from "../crypto.js";

/** Clients that cannot keep a secret (SPAs, mobile, desktop) must use PKCE and get no secret. */
export const PUBLIC_CLIENT = "public";
/** Clients with a server side that can hold a secret. */
export const CONFIDENTIAL_CLIENT = "confidential";

/**
 * @typedef {object} OidcClient
 * @property {string} client_id
 * @property {string} [client_secret]      Confidential clients only.
 * @property {string} client_name          Shown on the consent screen. This is what the user reads
 *                                         to decide, so it must be the real product name.
 * @property {string[]} redirect_uris      Exact-match allowlist.
 * @property {"public"|"confidential"} [type="public"]
 * @property {string[]} [scopes]           Scopes this client may request. Default ["openid","profile"].
 * @property {boolean} [first_party]       Skip the consent screen. Only for apps YOU ship — it is
 *                                         the difference between "the user agreed" and "we assumed".
 * @property {boolean} [pairwise]          Give this client a per-client `sub` (see subjectFor).
 * @property {Function} [authorize]        Optional extra gate on top of the provider-wide one.
 * @property {string[]} [post_logout_redirect_uris]
 */

/**
 * A registry backed by a plain array — the right choice until you have enough clients that editing
 * a config is annoying. Everything is validated at construction so a typo fails at deploy rather
 * than at someone's first sign-in.
 */
export class StaticClientRegistry {
  constructor(clients) {
    if (!Array.isArray(clients) || clients.length === 0) {
      throw new Error("StaticClientRegistry: at least one client is required");
    }
    this.clients = new Map();
    for (const client of clients) {
      const validated = validateClient(client);
      if (this.clients.has(validated.client_id)) {
        throw new Error(`StaticClientRegistry: duplicate client_id ${JSON.stringify(validated.client_id)}`);
      }
      this.clients.set(validated.client_id, validated);
    }
  }

  async get(clientId) {
    return this.clients.get(clientId) ?? null;
  }
}

/** A registry over any async key-value store — Workers KV, D1, Redis. */
export class StoreClientRegistry {
  /**
   * @param {object} store  Anything with `get(key)` returning the client JSON (or an object).
   * @param {object} [options]
   * @param {string} [options.prefix="oidc:client:"]
   */
  constructor(store, { prefix = "oidc:client:" } = {}) {
    if (!store) throw new Error("StoreClientRegistry: a store is required");
    this.store = store;
    this.prefix = prefix;
  }

  async get(clientId) {
    const raw = await this.store.get(`${this.prefix}${clientId}`, "json");
    if (!raw) return null;
    try {
      return validateClient(typeof raw === "string" ? JSON.parse(raw) : raw);
    } catch {
      // A malformed stored client is a configuration failure, not an authentication one: refuse
      // rather than fall back to something permissive.
      return null;
    }
  }
}

export function validateClient(client) {
  if (!client || typeof client.client_id !== "string" || !client.client_id) {
    throw new Error("client: `client_id` is required");
  }
  if (typeof client.client_name !== "string" || !client.client_name) {
    throw new Error(`client ${client.client_id}: \`client_name\` is required (it is shown on the consent screen)`);
  }
  if (!Array.isArray(client.redirect_uris) || client.redirect_uris.length === 0) {
    throw new Error(`client ${client.client_id}: at least one \`redirect_uris\` entry is required`);
  }

  for (const uri of client.redirect_uris) {
    assertUsableRedirectUri(client.client_id, uri);
  }

  const type = client.type ?? PUBLIC_CLIENT;
  if (type !== PUBLIC_CLIENT && type !== CONFIDENTIAL_CLIENT) {
    throw new Error(`client ${client.client_id}: \`type\` must be "public" or "confidential"`);
  }
  if (type === CONFIDENTIAL_CLIENT && !client.client_secret) {
    throw new Error(`client ${client.client_id}: confidential clients need a \`client_secret\``);
  }
  if (type === PUBLIC_CLIENT && client.client_secret) {
    throw new Error(`client ${client.client_id}: public clients must not have a \`client_secret\` — it cannot be kept`);
  }

  return {
    ...client,
    type,
    scopes: client.scopes ?? ["openid", "profile"],
    first_party: Boolean(client.first_party),
    pairwise: Boolean(client.pairwise),
  };
}

function assertUsableRedirectUri(clientId, uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error(`client ${clientId}: redirect_uri ${JSON.stringify(uri)} is not an absolute URI`);
  }

  // A fragment is never sent to the server and the spec forbids one here outright.
  if (parsed.hash) {
    throw new Error(`client ${clientId}: redirect_uri ${JSON.stringify(uri)} must not contain a fragment`);
  }

  // http is allowed only for loopback, which is how native apps receive a callback. Anywhere else
  // it means codes crossing the network in clear text.
  const isLoopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]" || parsed.hostname === "localhost";
  const isPrivateScheme = parsed.protocol !== "http:" && parsed.protocol !== "https:"; // com.example.app:/cb
  if (parsed.protocol === "http:" && !isLoopback) {
    throw new Error(`client ${clientId}: redirect_uri ${JSON.stringify(uri)} must use https (http is allowed only for loopback)`);
  }
  if (!isPrivateScheme && parsed.protocol !== "https:" && !isLoopback) {
    throw new Error(`client ${clientId}: redirect_uri ${JSON.stringify(uri)} has an unsupported scheme`);
  }
}

/**
 * Exact-match check. Deliberately not "starts with", not "same origin", not "ignoring trailing
 * slash" — every one of those has been someone's CVE.
 *
 * The one concession is a loopback port: native apps bind whatever port the OS gives them, so
 * RFC 8252 says the provider must ignore the port for loopback and only for loopback.
 */
export function matchRedirectUri(client, candidate) {
  if (typeof candidate !== "string" || !candidate) return null;

  if (client.redirect_uris.includes(candidate)) return candidate;

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return null;
  }
  const isLoopback =
    parsed.protocol === "http:" && (parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]");
  if (!isLoopback) return null;

  for (const registered of client.redirect_uris) {
    let known;
    try {
      known = new URL(registered);
    } catch {
      continue;
    }
    if (
      known.protocol === parsed.protocol &&
      known.hostname === parsed.hostname &&
      known.pathname === parsed.pathname &&
      known.search === parsed.search
    ) {
      return candidate;
    }
  }
  return null;
}

/** Constant-time client secret check. */
export async function verifyClientSecret(client, presented) {
  if (!client.client_secret || typeof presented !== "string") return false;
  // Compare digests rather than the raw strings so the comparison is fixed-length regardless of
  // what was presented, and the length of the real secret does not leak.
  const key = new TextEncoder().encode("OidcClientSecretCompare");
  const [expected, actual] = await Promise.all([
    hmacSha256(key, client.client_secret).then(toHex),
    hmacSha256(key, presented).then(toHex),
  ]);
  return timingSafeEqualHex(expected, actual);
}

/**
 * The `sub` claim a given client sees for a given user.
 *
 * Public mode hands every client the same Telegram user id — simple, and fine among your own apps.
 * Pairwise mode gives each client a different opaque id for the same person, so two relying parties
 * comparing notes cannot tell they are talking about the same user. For a service that third
 * parties integrate with, that is the difference between an identity provider and a tracking
 * network, and it costs one HMAC.
 */
export async function subjectFor(client, userId, pairwiseSalt) {
  if (!client.pairwise) return String(userId);
  if (!pairwiseSalt) throw new Error("subjectFor: pairwise clients need `pairwiseSalt` configured");
  const sectorId = sectorIdentifierFor(client);
  const digest = await hmacSha256(new TextEncoder().encode(pairwiseSalt), `${sectorId}|${userId}`);
  return toHex(digest).slice(0, 32);
}

/**
 * Clients sharing a sector get the same pairwise sub, which is what lets one vendor's several apps
 * recognise a returning user. Defaults to the host of the first redirect_uri.
 */
export function sectorIdentifierFor(client) {
  if (client.sector_identifier) return client.sector_identifier;
  try {
    return new URL(client.redirect_uris[0]).host;
  } catch {
    return client.client_id;
  }
}
