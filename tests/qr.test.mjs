import test from "node:test";
import assert from "node:assert/strict";

import { qrSvg, qrDataUri } from "../src/qr.js";
import { renderLoginPage } from "../src/login-page.js";
import { randomToken, tokenPattern, timingSafeEqualHex } from "../src/crypto.js";

const DEEP_LINK = "https://t.me/example_bot?start=cockpit_0123456789abcdef0123456789abcdef";

test("qrSvg produces a self-contained SVG with no external references", () => {
  const svg = qrSvg(DEEP_LINK);
  assert.match(svg, /^<svg /);
  assert.match(svg, /<\/svg>$/);
  assert.match(svg, /viewBox="0 0 \d+ \d+"/);
  assert.match(svg, /<path d="M/);
  // The whole point: nothing is fetched to render this.
  assert.equal(/https?:\/\//.test(svg.replace('xmlns="http://www.w3.org/2000/svg"', "")), false);
  assert.equal(/<image|<script|xlink:href/.test(svg), false);
});

test("qrSvg picks a version that fits, however long the link", () => {
  const short = qrSvg("https://t.me/b?start=a_1");
  const long = qrSvg(`https://auth.example.com/very/long/path?start=${"x".repeat(400)}`);
  const sizeOf = (svg) => Number(svg.match(/viewBox="0 0 (\d+)/)[1]);
  assert.ok(sizeOf(long) > sizeOf(short));
});

test("qrSvg is styleable without breaking scannability", () => {
  const svg = qrSvg(DEEP_LINK, { cellSize: 8, margin: 6, dark: "#111827", light: "#f9fafb" });
  assert.match(svg, /fill="#111827"/);
  assert.match(svg, /fill="#f9fafb"/);
  // Quiet zone included in the canvas.
  const modules = qrSvg(DEEP_LINK, { cellSize: 1, margin: 0 }).match(/viewBox="0 0 (\d+)/)[1];
  const withMargin = qrSvg(DEEP_LINK, { cellSize: 1, margin: 6 }).match(/viewBox="0 0 (\d+)/)[1];
  assert.equal(Number(withMargin), Number(modules) + 12);
});

test("qrSvg escapes anything interpolated into attributes", () => {
  const svg = qrSvg(DEEP_LINK, { label: '"><script>alert(1)</script>' });
  assert.equal(/<script>/.test(svg), false);
  assert.match(svg, /&quot;&gt;&lt;script&gt;/);
});

test("qrDataUri returns a decodable image/svg+xml URI", () => {
  const uri = qrDataUri(DEEP_LINK);
  assert.match(uri, /^data:image\/svg\+xml;base64,/);
  const decoded = Buffer.from(uri.split(",")[1], "base64").toString("utf8");
  assert.match(decoded, /^<svg /);
});

test("the login page escapes the deep link and the branding it is given", () => {
  const html = renderLoginPage({
    token: "0".repeat(32),
    deepLink: 'https://t.me/bot?start=a"onload="alert(1)',
    qrSvg: "<svg></svg>",
    pollPath: "/auth/poll",
    error: "<img src=x onerror=alert(1)>",
    branding: { heading: "</h1><script>alert(1)</script>" },
  });
  assert.equal(/onload="alert/.test(html), false);
  assert.equal(/<img src=x/.test(html), false);
  assert.equal(/<script>alert\(1\)<\/script>/.test(html), false);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test("the login page keeps search engines out and asks for no input", () => {
  const html = renderLoginPage({ token: "0".repeat(32), deepLink: "https://t.me/b?start=a_1", qrSvg: "<svg></svg>", pollPath: "/auth/poll" });
  assert.match(html, /<meta name="robots" content="noindex, nofollow">/);
  assert.equal(/<input|<form|<textarea/i.test(html), false);
});

test("tokens are 128 bits of hex and match their own pattern", () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) {
    const token = randomToken();
    assert.match(token, /^[0-9a-f]{32}$/);
    assert.equal(seen.has(token), false, "randomToken must not repeat");
    seen.add(token);
    assert.equal(tokenPattern().test(token), true);
  }
  assert.match(randomToken(32), /^[0-9a-f]{64}$/);
  assert.equal(tokenPattern(32).test(randomToken(32)), true);
  assert.equal(tokenPattern(16).test(randomToken(32)), false);
});

test("timingSafeEqualHex compares by value", () => {
  assert.equal(timingSafeEqualHex("abc123", "abc123"), true);
  assert.equal(timingSafeEqualHex("abc123", "abc124"), false);
  assert.equal(timingSafeEqualHex("abc123", "abc12"), false);
  assert.equal(timingSafeEqualHex("", ""), true);
});

test("the QR is a link to the deep link it encodes, opening in a new tab so polling continues", () => {
  const deepLink = "https://t.me/b?start=a_1";
  const html = renderLoginPage({ token: "0".repeat(32), deepLink, qrSvg: "<svg></svg>", pollPath: "/auth/poll" });
  const qr = html.match(/<div class="tqa-qr" id="tqa-qr">(.*?)<\/div>/s)[1];
  assert.match(qr, new RegExp(`<a [^>]*href="${deepLink.replace(/[?.]/g, "\\$&")}"`));
  assert.match(qr, /target="_blank"/);
  assert.match(qr, /rel="noopener noreferrer"/);
  assert.match(qr, /<svg><\/svg>/, "the QR image must sit inside the link");
});

test("touch devices get an Open Telegram button and their own subtitle; both are customisable", () => {
  const html = renderLoginPage({
    token: "0".repeat(32),
    deepLink: "https://t.me/b?start=a_1",
    qrSvg: "<svg></svg>",
    pollPath: "/auth/poll",
    branding: { mobileLinkText: "Ouvrir Telegram", mobileSubtitle: "Touchez le bouton", qrHintText: "Cliquez sur le code" },
  });
  assert.match(html, /<a class="tqa-open tqa-touch-only"[^>]*href="https:\/\/t\.me\/b\?start=a_1"[^>]*>Ouvrir Telegram<\/a>/);
  assert.match(html, /tqa-touch-only">Touchez le bouton/);
  assert.match(html, /tqa-pointer-only" id="tqa-hint">Cliquez sur le code/);
  assert.match(html, /@media \(hover: none\) and \(pointer: coarse\)/);
});

test("the open-Telegram links are hidden once the sign-in expires or is denied", () => {
  const html = renderLoginPage({ token: "0".repeat(32), deepLink: "https://t.me/b?start=a_1", qrSvg: "<svg></svg>", pollPath: "/auth/poll" });
  assert.match(html, /function hideOpenLinks/);
  assert.match(html, /function showExpired\(\) \{\s*stopped = true;\s*hideOpenLinks\(\);/);
  assert.match(html, /status === "denied"\) \{\s*stopped = true;\s*hideOpenLinks\(\);/);
});
