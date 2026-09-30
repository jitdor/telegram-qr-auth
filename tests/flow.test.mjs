// The end-to-end sign-in flow, and the ways it is supposed to refuse.

import test from "node:test";
import assert from "node:assert/strict";

import { createTelegramQrAuth, sameSitePath, LOGIN_PAGE_HEADER } from "../src/provider.js";
import { D1LoginStore } from "../src/stores/d1.js";
import { MemoryLoginStore } from "../src/stores/memory.js";
import { DoLoginStore, defineQrAuthStorage } from "../src/do.js";
import { chatMember, allowlist } from "../src/gates.js";
import { makeFakeD1, makeFakeDONamespace, makeFakeTelegram, makeRequest, cookieFrom, ALICE, MALLORY } from "./helpers.mjs";

const CHAT_ID = "-1001234567890";

function setup({ members = [ALICE.id], authorize, ...overrides } = {}) {
  const db = makeFakeD1();
  const telegram = makeFakeTelegram({ members });
  const auth = createTelegramQrAuth({
    botToken: "123:TEST",
    botUsername: "example_bot",
    store: new D1LoginStore(db),
    namespace: "cockpit",
    telegram,
    authorize: authorize ?? chatMember({ chatId: CHAT_ID, onError: () => {} }),
    ...overrides,
  });
  return { auth, telegram, db };
}

async function pollOnce(auth, token) {
  return auth.poll(makeRequest(`https://app.example/auth/poll?token=${token}`));
}

test("scan to session: the whole happy path", async () => {
  const { auth } = setup();

  const { token, deepLink, svg } = await auth.beginLogin();
  assert.equal(deepLink, `https://t.me/example_bot?start=cockpit_${token}`);
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);

  // Before the scan the page just waits.
  assert.deepEqual(await (await pollOnce(auth, token)).json(), { status: "pending" });

  // The bot receives "/start cockpit_<token>" and confirms it.
  const started = await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });
  assert.equal(started.matched, true);
  assert.equal(started.ok, true);

  // The next poll hands back the session cookie.
  const response = await pollOnce(auth, token);
  assert.deepEqual(await response.json(), { status: "confirmed" });
  const cookie = cookieFrom(response, auth.cookieName);
  assert.ok(cookie, "expected a session cookie");
  assert.match(response.headers.get("Set-Cookie"), /HttpOnly/);
  assert.match(response.headers.get("Set-Cookie"), /Secure/);
  assert.match(response.headers.get("Set-Cookie"), /SameSite=Lax/);

  // And that cookie gets past the guard, carrying the scanner's identity.
  const guarded = await auth.guard(makeRequest("https://app.example/", { cookie: `${auth.cookieName}=${cookie}` }));
  assert.equal(guarded.ok, true);
  assert.equal(guarded.session.id, ALICE.id);
  assert.equal(guarded.session.name, "Alice Ng");
});

test("the user types nothing: the deep link carries the whole credential", async () => {
  const { auth } = setup();
  const { deepLink, payload, token } = await auth.beginLogin();
  // Everything the flow needs is in the URL the QR encodes — no field on the page accepts input,
  // and the only thing the user's phone sends is this exact payload.
  assert.equal(payload, `cockpit_${token}`);
  assert.equal(auth.parseStartPayload(deepLink.split("?start=")[1]), token);

  const html = await auth.loginPage();
  assert.equal(/<input\b/i.test(html), false, "the sign-in page must have no input fields");
  assert.equal(/<form\b/i.test(html), false, "the sign-in page must have no forms");
});

test("a token is single-use: the second poll gets nothing", async () => {
  const { auth } = setup();
  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });

  assert.equal((await (await pollOnce(auth, token)).json()).status, "confirmed");
  assert.equal((await (await pollOnce(auth, token)).json()).status, "invalid");
});

test("a token cannot be confirmed twice", async () => {
  const { auth } = setup({ members: [ALICE.id, MALLORY.id] });
  const { token } = await auth.beginLogin();

  assert.equal((await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE })).ok, true);
  const second = await auth.handleStart({ text: `/start cockpit_${token}`, from: MALLORY });
  assert.equal(second.ok, false);
  assert.equal(second.reason, "unknown_or_used");

  // The session that comes out belongs to whoever scanned first.
  const response = await pollOnce(auth, token);
  const cookie = cookieFrom(response, auth.cookieName);
  const session = await auth.session.verify(cookie);
  assert.equal(session.id, ALICE.id);
});

test("an unauthorized scan is refused and does not burn the token", async () => {
  const { auth } = setup({ members: [ALICE.id] });
  const { token } = await auth.beginLogin();

  const denied = await auth.handleStart({ text: `/start cockpit_${token}`, from: MALLORY });
  assert.equal(denied.ok, false);
  assert.equal(denied.reason, "not_a_member");
  assert.match(denied.replyText, /not authorized/i);

  // Still pending — the person it was meant for can scan the very same QR.
  assert.equal((await (await pollOnce(auth, token)).json()).status, "pending");
  assert.equal((await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE })).ok, true);
});

test("expired tokens report expired, then stop existing", async () => {
  let clock = 1_700_000_000;
  const { auth } = setup({ now: () => clock, tokenTtlSeconds: 600 });
  const { token } = await auth.beginLogin();

  clock += 601;
  assert.equal((await (await pollOnce(auth, token)).json()).status, "expired");
  assert.equal((await (await pollOnce(auth, token)).json()).status, "invalid");
});

test("a token that expires before the scan cannot be confirmed", async () => {
  let clock = 1_700_000_000;
  const { auth } = setup({ now: () => clock, tokenTtlSeconds: 600 });
  const { token } = await auth.beginLogin();

  clock += 601;
  const late = await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });
  assert.equal(late.ok, false);
  assert.equal(late.reason, "unknown_or_used");
});

test("garbage tokens never reach the store", async () => {
  const { auth, db } = setup();
  let queries = 0;
  const realPrepare = db.prepare.bind(db);
  db.prepare = (sql) => {
    queries++;
    return realPrepare(sql);
  };

  for (const bad of ["", "not-hex", "../../etc/passwd", "a".repeat(31), "A".repeat(32), "0".repeat(33)]) {
    const response = await auth.poll(makeRequest(`https://app.example/auth/poll?token=${encodeURIComponent(bad)}`));
    assert.equal((await response.json()).status, "invalid");
  }
  assert.equal(queries, 0, "malformed tokens must be rejected before any DB access");
});

test("revocation takes effect on the next request, not at cookie expiry", async () => {
  const { auth, telegram } = setup();
  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });
  const cookie = cookieFrom(await pollOnce(auth, token), auth.cookieName);

  const request = makeRequest("https://app.example/", { cookie: `${auth.cookieName}=${cookie}` });
  assert.equal((await auth.guard(request)).ok, true);

  telegram.memberIds.delete(ALICE.id); // removed from the group

  const after = await auth.guard(request);
  assert.equal(after.ok, false);
  assert.equal(after.reason, "not_a_member");
  assert.equal(after.response.status, 403);
  // The now-worthless cookie is torn up rather than left to expire on its own.
  assert.match(after.response.headers.get("Set-Cookie"), /Max-Age=0/);
});

test("a confirmed scan is still refused at poll time if authorization lapsed in between", async () => {
  const { auth, telegram } = setup();
  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });

  telegram.memberIds.delete(ALICE.id); // removed between the scan and the poll

  const response = await pollOnce(auth, token);
  assert.deepEqual(await response.json(), { status: "denied", reason: "not_a_member" });
  assert.equal(response.headers.get("Set-Cookie"), null);
});

test("one bot, several apps: namespaces do not cross", async () => {
  const db = makeFakeD1();
  const telegram = makeFakeTelegram({ members: [ALICE.id] });
  const common = { botToken: "123:TEST", botUsername: "example_bot", telegram, authorize: allowlist([ALICE.id]) };
  const cockpit = createTelegramQrAuth({ ...common, namespace: "cockpit", store: new D1LoginStore(db) });
  const admin = createTelegramQrAuth({ ...common, namespace: "admin", store: new D1LoginStore(db) });

  const { token } = await cockpit.beginLogin();

  // The admin app doesn't recognize the cockpit's payload at all, so its bot handler stays silent.
  assert.equal(admin.parseStartPayload(`/start cockpit_${token}`), null);
  assert.deepEqual(await admin.handleStart({ text: `/start cockpit_${token}`, from: ALICE }), { matched: false });

  // And a cockpit token is invisible to the admin app's poll endpoint even by its raw value.
  assert.equal((await (await pollOnce(admin, token)).json()).status, "invalid");

  assert.equal((await cockpit.handleStart({ text: `/start cockpit_${token}`, from: ALICE })).ok, true);
  assert.notEqual(cockpit.cookieName, admin.cookieName);
});

test("the /auth router owns its paths and nothing else", async () => {
  const { auth } = setup();

  assert.equal(await auth.handle(makeRequest("https://app.example/")), null);
  assert.equal(await auth.handle(makeRequest("https://app.example/dashboard")), null);

  const login = await auth.handle(makeRequest("https://app.example/auth/login"));
  assert.equal(login.status, 200);
  assert.match(login.headers.get("Content-Type"), /text\/html/);
  assert.match(login.headers.get("Cache-Control"), /no-store/);

  const qr = await auth.handle(makeRequest("https://app.example/auth/qr"));
  const body = await qr.json();
  assert.match(body.deepLink, /^https:\/\/t\.me\/example_bot\?start=cockpit_[0-9a-f]{32}$/);
  assert.equal(body.pollPath, "/auth/poll");

  const logout = await auth.handle(makeRequest("https://app.example/auth/logout"));
  assert.equal(logout.status, 302);
  assert.match(logout.headers.get("Set-Cookie"), /Max-Age=0/);
});

test("guard on a signed-out request serves the sign-in page with a fresh QR", async () => {
  const { auth } = setup();
  const first = await auth.guard(makeRequest("https://app.example/"));
  assert.equal(first.ok, false);
  assert.equal(first.reason, "unauthenticated");
  assert.equal(first.response.status, 200);

  const html = await first.response.text();
  assert.match(html, /<svg/);
  const [, tokenInPage] = html.match(/"token":"([0-9a-f]{32})"/);
  assert.equal((await (await pollOnce(auth, tokenInPage)).json()).status, "pending");
});

test("mint-time client context is captured and handed to the bot", async () => {
  const { auth } = setup();
  const request = makeRequest("https://app.example/auth/login", {
    headers: { "CF-Connecting-IP": "203.0.113.7", "User-Agent": "Mozilla/5.0 (Macintosh) Chrome/120" },
  });
  const { token } = await auth.beginLogin({ request });

  const result = await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });
  assert.equal(result.client.ip, "203.0.113.7");
  assert.equal(result.client.origin, "https://app.example");
});

test("captureClient: false stores nothing about the browser", async () => {
  const { auth } = setup({ captureClient: false });
  const request = makeRequest("https://app.example/auth/login", { headers: { "CF-Connecting-IP": "203.0.113.7" } });
  const { token } = await auth.beginLogin({ request });
  const record = await auth.store.get(token, "cockpit");
  assert.equal(record.client, null);
});

test("config mistakes fail at construction, not at 3am", () => {
  const store = new D1LoginStore(makeFakeD1());
  const base = { botToken: "123:TEST", botUsername: "example_bot", store };

  assert.throws(() => createTelegramQrAuth({ ...base, store: undefined }), /store/);
  assert.throws(() => createTelegramQrAuth({ ...base, botUsername: undefined }), /botUsername/);
  assert.throws(() => createTelegramQrAuth({ ...base, botToken: undefined, telegram: undefined }), /botToken/);
  // "_" is the payload separator, so it cannot appear in a namespace.
  assert.throws(() => createTelegramQrAuth({ ...base, namespace: "my_app" }), /namespace/);
  assert.throws(() => createTelegramQrAuth({ ...base, namespace: "" }), /namespace/);
});

// ---- Telegram outage ----------------------------------------------------------------------------

function outageTelegram(members = [ALICE.id]) {
  const telegram = makeFakeTelegram({ members });
  const state = { down: false };
  const call = telegram.call.bind(telegram);
  telegram.call = async (method, payload) => {
    if (state.down && method === "getChatMember") throw new Error("502 Bad Gateway");
    return call(method, payload);
  };
  return { telegram, state };
}

test("guard during a Telegram outage answers 503 and keeps the session, instead of signing the user out", async () => {
  const { telegram, state } = outageTelegram();
  const { auth } = setup({ telegram });

  const { token } = await auth.beginLogin();
  await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });
  const cookie = `${auth.cookieName}=${cookieFrom(await pollOnce(auth, token), auth.cookieName)}`;
  assert.equal((await auth.guard(makeRequest("https://app.example/", { cookie }))).ok, true);

  state.down = true;
  const during = await auth.guard(makeRequest("https://app.example/", { cookie }));
  assert.equal(during.ok, false);
  assert.equal(during.reason, "telegram_unavailable");
  assert.equal(during.response.status, 503);
  assert.equal(during.response.headers.get("Set-Cookie"), null, "an outage must not clear the session cookie");

  state.down = false;
  assert.equal((await auth.guard(makeRequest("https://app.example/", { cookie }))).ok, true, "same cookie works again");
});

test("a scan during an outage tells the user to scan again, and the QR is not spent", async () => {
  const { telegram, state } = outageTelegram();
  const { auth } = setup({ telegram });
  const { token } = await auth.beginLogin();

  state.down = true;
  const during = await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });
  assert.equal(during.ok, false);
  assert.equal(during.reason, "telegram_unavailable");
  assert.match(during.replyText, /scan the same QR code again/i);

  state.down = false;
  const after = await auth.handleStart({ text: `/start cockpit_${token}`, from: ALICE });
  assert.equal(after.ok, true, "the token survived the outage");
});

function redirectIn(html) {
  return JSON.parse(`"${html.match(/"redirectTo":"((?:[^"\\]|\\.)*)"/)[1]}"`);
}

test("beginLogin and /auth/qr hand out a tg:// app link beside the https deep link", async () => {
  const { auth } = setup();
  const { token, appLink } = await auth.beginLogin();
  assert.equal(appLink, `tg://resolve?domain=example_bot&start=cockpit_${token}`);
  assert.equal(auth.appLinkFor(token), appLink);

  const body = await (await auth.handle(makeRequest("https://app.example/auth/qr"))).json();
  assert.equal(body.appLink, `tg://resolve?domain=example_bot&start=cockpit_${body.token}`);
  assert.equal(body.deepLink, `https://t.me/example_bot?start=cockpit_${body.token}`);
});

test("a signed-out deep link comes back to the page that was asked for", async () => {
  const { auth } = setup();
  const gate = await auth.guard(makeRequest("https://app.example/tickets/x.pdf?download=1"));
  assert.equal(redirectIn(await gate.response.text()), "/tickets/x.pdf?download=1");

  const explicit = await auth.guard(makeRequest("https://app.example/tickets/x.pdf"), { redirectTo: "/tickets" });
  assert.equal(redirectIn(await explicit.response.text()), "/tickets");

  // A POST cannot be replayed by a redirect, so it goes to the configured default.
  const post = await auth.guard(makeRequest("https://app.example/api/save", { method: "POST" }));
  assert.equal(redirectIn(await post.response.text()), "/");
});

test("the sign-in page only ever returns to a same-site path", async () => {
  const { auth } = setup({ redirectTo: "/home" });
  for (const hostile of ["https://evil.example/", "//evil.example/", "/\\evil.example/", "/\t/evil.example", "javascript:alert(1)", ""]) {
    const gate = await auth.guard(makeRequest("https://app.example/"), { redirectTo: hostile });
    assert.equal(redirectIn(await gate.response.text()), "/home", hostile);
    assert.equal(redirectIn(await auth.loginPage({ redirectTo: hostile })), "/home", hostile);
  }
  assert.equal(sameSitePath("/a/b?c=//d"), "/a/b?c=//d");
  assert.equal(sameSitePath("/"), "/");
  assert.equal(sameSitePath(null), null);
});

test("every sign-in page response is marked so a service worker can refuse to cache it", async () => {
  const { auth } = setup();
  const fromRoute = await auth.handle(makeRequest("https://app.example/auth/login"));
  assert.equal(fromRoute.headers.get(LOGIN_PAGE_HEADER), "login");
  assert.equal(LOGIN_PAGE_HEADER, "X-Telegram-Qr-Auth");
  const fromGuard = (await auth.guard(makeRequest("https://app.example/"))).response;
  assert.equal(fromGuard.headers.get("X-Telegram-Qr-Auth"), "login");
  assert.match(fromGuard.headers.get("Cache-Control"), /no-store/);
});

test("logoutResponse can also clear offline copies", async () => {
  const { auth } = setup();
  assert.equal(auth.logoutResponse().headers.get("Clear-Site-Data"), null);
  const response = auth.logoutResponse({ clearSiteData: true });
  assert.equal(response.headers.get("Clear-Site-Data"), '"cache", "storage"');
  assert.match(response.headers.get("Set-Cookie"), /cockpit_session=;/);
});

for (const [name, makeStore] of [
  ["MemoryLoginStore", () => new MemoryLoginStore()],
  ["D1LoginStore", () => new D1LoginStore(makeFakeD1())],
  ["DoLoginStore", () => new DoLoginStore(makeFakeDONamespace(defineQrAuthStorage))],
]) {
  test(`${name}: concurrent polls of one confirmation yield exactly one session`, async () => {
    const { auth } = setup({ store: makeStore(), authorize: allowlist([ALICE.id]) });
    const { token } = await auth.beginLogin();
    await auth.confirm({ token, user: ALICE });

    const responses = await Promise.all(Array.from({ length: 5 }, () => pollOnce(auth, token)));
    const bodies = await Promise.all(responses.map((r) => r.json()));
    const cookies = responses.map((r) => cookieFrom(r, auth.cookieName)).filter(Boolean);

    assert.equal(bodies.filter((b) => b.status === "confirmed").length, 1, JSON.stringify(bodies));
    assert.equal(cookies.length, 1, "only the winning poll carries a session cookie");
    assert.ok(bodies.every((b) => b.status === "confirmed" || b.status === "invalid"));
  });
}

test("a confirmation nobody collected before the TTL is expired, not a session", async () => {
  let clock = Math.floor(Date.now() / 1000);
  const { auth } = setup({ now: () => clock, tokenTtlSeconds: 60 });
  const { token } = await auth.beginLogin();
  assert.equal((await auth.confirm({ token, user: ALICE })).ok, true);

  clock += 61;
  const response = await pollOnce(auth, token);
  assert.deepEqual(await response.json(), { status: "expired" });
  assert.equal(cookieFrom(response, auth.cookieName), null);
  assert.equal(await auth.store.get(token, "cockpit"), null, "and it is gone");
});

test("a bring-your-own store without consume() still works", async () => {
  const inner = new MemoryLoginStore();
  const legacy = {
    create: (r) => inner.create(r),
    get: (t, n) => inner.get(t, n),
    confirm: (t, n, u) => inner.confirm(t, n, u),
    remove: (t, n) => inner.remove(t, n),
  };
  const { auth } = setup({ store: legacy, authorize: allowlist([ALICE.id]) });
  const { token } = await auth.beginLogin();
  await auth.confirm({ token, user: ALICE });
  assert.equal((await (await pollOnce(auth, token)).json()).status, "confirmed");
  assert.equal((await (await pollOnce(auth, token)).json()).status, "invalid");
});
