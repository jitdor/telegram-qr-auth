import test from "node:test";
import assert from "node:assert/strict";

import { qrSvg, qrDataUri } from "../src/qr.js";
import vm from "node:vm";
import { renderLoginPage, pollScript, appLinkFromDeepLink } from "../src/login-page.js";
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

const APP_LINK_HTML = "tg://resolve?domain=b&amp;start=a_1";

test("the QR encodes the https link but, like the button, opens the tg:// app link in place", () => {
  const html = renderLoginPage({ token: "0".repeat(32), deepLink: "https://t.me/b?start=a_1", qrSvg: "<svg></svg>", pollPath: "/auth/poll" });
  const qr = html.match(/<div class="tqa-qr" id="tqa-qr">(.*?)<\/div>/s)[1];
  assert.match(qr, new RegExp(`<a [^>]*href="${APP_LINK_HTML.replace(/[?.]/g, "\\$&")}"`));
  // A new tab would be left behind as a blank page; an app link never navigates this one away.
  assert.doesNotMatch(qr, /target=/);
  assert.match(qr, /<svg><\/svg>/, "the QR image must sit inside the link");
});

test("an explicit appLink wins over the derived one", () => {
  const html = renderLoginPage({ token: "0".repeat(32), deepLink: "https://t.me/b?start=a_1", appLink: "tg://x", qrSvg: "", pollPath: "/p" });
  assert.match(html, /id="tqa-open" href="tg:\/\/x"/);
});

test("appLinkFromDeepLink maps t.me links and leaves anything else alone", () => {
  assert.equal(appLinkFromDeepLink("https://t.me/example_bot?start=cockpit_abc"), "tg://resolve?domain=example_bot&start=cockpit_abc");
  assert.equal(appLinkFromDeepLink("https://t.me/example_bot"), "tg://resolve?domain=example_bot");
  assert.equal(appLinkFromDeepLink("https://example.com/x?start=1"), "https://example.com/x?start=1");
  assert.equal(appLinkFromDeepLink("not a url"), "not a url");
});

test("touch devices get an Open Telegram button and their own subtitle; both are customisable", () => {
  const html = renderLoginPage({
    token: "0".repeat(32),
    deepLink: "https://t.me/b?start=a_1",
    qrSvg: "<svg></svg>",
    pollPath: "/auth/poll",
    branding: { mobileLinkText: "Ouvrir Telegram", mobileSubtitle: "Touchez le bouton", qrHintText: "Cliquez sur le code" },
  });
  assert.match(html, /<a class="tqa-open tqa-touch-only"[^>]*href="tg:\/\/resolve\?domain=b&amp;start=a_1"[^>]*><svg[^]*?<span>Ouvrir Telegram<\/span><\/a>/);
  assert.match(html, /tqa-touch-only" id="tqa-how">Touchez le bouton/);
  assert.match(html, /tqa-pointer-only" id="tqa-hint">Cliquez sur le code/);
  assert.match(html, /@media \(hover: none\) and \(pointer: coarse\)/);
});

test("the default mobile copy explains the Start button an existing chat shows", () => {
  const html = renderLoginPage({ token: "0".repeat(32), deepLink: "https://t.me/b?start=a_1", qrSvg: "", pollPath: "/p" });
  assert.match(html, /Tap Start at the bottom of the chat, then come back to this tab/);
});

test("branding text cannot close the script element it is embedded in", () => {
  const html = renderLoginPage({
    token: "0".repeat(32),
    deepLink: "https://t.me/b?start=a_1",
    qrSvg: "",
    pollPath: "/p",
    branding: { successText: "</script><script>alert(1)</script>" },
  });
  assert.equal(html.match(/<\/script>/g).length, 1);
});

/**
 * Runs pollScript against a minimal fake DOM, with fetch and timers under the test's control.
 * `respond(status)` settles the oldest outstanding poll.
 */
function runPollScript(options = {}) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, { id, hidden: false, textContent: "", children: [], appendChild(child) { this.children.push(child); } });
    }
    return elements.get(id);
  };
  for (const id of ["tqa-status", "tqa-qr", "tqa-open", "tqa-hint"]) element(id);

  const listeners = {};
  const rootAttributes = {};
  const timers = new Map();
  let nextTimer = 1;
  const pending = [];
  const document = {
    visibilityState: "visible",
    documentElement: { setAttribute: (name, value) => (rootAttributes[name] = value) },
    getElementById: (id) => elements.get(id) ?? null,
    createElement: () => ({ addEventListener() {} }),
    addEventListener: (type, fn) => (listeners[type] = fn),
  };
  const window = { location: { href: "/auth/login", reload() {} } };
  const context = {
    document,
    window,
    fetch: (url) => new Promise((resolve) => pending.push({ url, resolve })),
    setTimeout: (fn, delay) => {
      const id = nextTimer++;
      timers.set(id, { fn, delay });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
    encodeURIComponent,
  };
  vm.runInNewContext(pollScript({ token: "t0k", pollPath: "/auth/poll", redirectTo: "/next", pollIntervalMs: 2000, ...options }), context);

  const flush = () => new Promise((resolve) => setImmediate(resolve));
  return {
    elements,
    rootAttributes,
    timers,
    pending,
    window,
    document,
    fireTimers() {
      const due = [...timers.values()];
      timers.clear();
      for (const { fn } of due) fn();
    },
    showTab() {
      document.visibilityState = "visible";
      listeners.visibilitychange();
    },
    async respond(status) {
      pending.shift().resolve({ json: async () => ({ status }) });
      await flush();
    },
  };
}

test("pollScript: polls on a timer and follows the redirect when confirmed", async () => {
  const page = runPollScript();
  assert.equal(page.rootAttributes["data-tqa-state"], "waiting");
  assert.equal(page.timers.size, 1);
  page.fireTimers();
  assert.equal(page.pending.length, 1);
  assert.equal(page.pending[0].url, "/auth/poll?token=t0k");

  await page.respond("pending");
  assert.equal(page.timers.size, 1, "exactly one next poll is scheduled");
  page.fireTimers();
  await page.respond("confirmed");
  assert.equal(page.window.location.href, "/next");
  assert.equal(page.rootAttributes["data-tqa-state"], "signed-in");
  assert.equal(page.timers.size, 0);
});

test("pollScript: returning to the tab polls at once, without starting a second loop", async () => {
  const page = runPollScript();
  page.showTab();
  assert.equal(page.pending.length, 1, "polled immediately");
  assert.equal(page.timers.size, 0, "the pending timer was replaced, not doubled");

  page.showTab();
  assert.equal(page.pending.length, 1, "no second request while one is in flight");

  await page.respond("pending");
  assert.equal(page.timers.size, 1);
});

test("pollScript: expired and denied stop the loop and hide the dead links", async () => {
  const expired = runPollScript();
  expired.fireTimers();
  await expired.respond("expired");
  assert.equal(expired.elements.get("tqa-open").hidden, true);
  assert.equal(expired.elements.get("tqa-hint").hidden, true);
  assert.equal(expired.elements.get("tqa-qr").children.length, 1, "the QR was replaced by a retry button");
  assert.equal(expired.rootAttributes["data-tqa-state"], "expired");
  expired.showTab();
  assert.equal(expired.pending.length, 0, "nothing polls after the sign-in is over");

  const denied = runPollScript({ texts: { denied: "Nope" } });
  denied.fireTimers();
  await denied.respond("denied");
  assert.equal(denied.elements.get("tqa-status").textContent, "Nope");
  assert.equal(denied.elements.get("tqa-open").hidden, true);
  assert.equal(denied.rootAttributes["data-tqa-state"], "denied");
  assert.equal(denied.timers.size, 0);
});

test("pollScript: invalid is treated as expired, and custom ids are honoured", async () => {
  const page = runPollScript({ ids: { status: "tqa-status", qr: null, hide: ["tqa-hint"] } });
  page.fireTimers();
  await page.respond("invalid");
  assert.equal(page.rootAttributes["data-tqa-state"], "expired");
  assert.equal(page.elements.get("tqa-hint").hidden, true);
  assert.equal(page.elements.get("tqa-open").hidden, false, "only the listed ids are hidden");
  assert.equal(page.elements.get("tqa-qr").children.length, 0, "no QR container, no retry button");
});
