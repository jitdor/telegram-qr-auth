// telegram-qr-auth/oidc — a standards-compliant OpenID Connect provider whose authentication
// method is a Telegram QR scan.
//
// Use this instead of the base package when apps you do not control need to sign users in. The
// base package's HMAC sessions are fine among your own apps; they are not fine across a trust
// boundary, because a party that can verify one can also forge one. Here the provider holds an
// ECDSA private key, publishes only public keys, and scopes every token to one audience.
//
// See ../../docs/oidc.md for the deployment guide.

export { createOidcProvider } from "./provider.js";

export { generateSigningKey, loadSigningKeys, toJwks, jwkThumbprint, importPublicJwk, SIGNING_ALG } from "./keys.js";
export { signJwt, verifyJwt, decodeJwt } from "./jwt.js";

export {
  StaticClientRegistry,
  StoreClientRegistry,
  validateClient,
  matchRedirectUri,
  verifyClientSecret,
  subjectFor,
  sectorIdentifierFor,
  PUBLIC_CLIENT,
  CONFIDENTIAL_CLIENT,
} from "./clients.js";

export { MemoryOidcStore, KvOidcStore } from "./store.js";
export { D1OidcStore } from "./d1-store.js";
export { DoOidcStore } from "../do.js";
export { createPkcePair, deriveChallenge, verifyChallenge, isValidChallenge, isValidVerifier, S256 } from "./pkce.js";
export { renderConsentPage, renderErrorPage, SCOPE_DESCRIPTIONS } from "./consent-page.js";
