import test from "node:test";
import assert from "node:assert/strict";

import { createTelegramQrAuth } from "../src/provider.js";
import { createStartHandler, createWebhookHandler } from "../src/bot.js";
import { MemoryLoginStore } from "../src/stores/memory.js";
import { allowlist } from "../src/gates.js";
import { makeFakeTelegram, makeRequest, ALICE, MALLORY } from "./helpers.mjs";

function setup(options = {}) {
  const telegram = makeFakeTelegram({ members: [ALICE.id] });
  const auth = createTelegramQrAuth({
    botToken: "123:TEST",
    botUsername: "example_bot",
    store: new MemoryLoginStore(),
    namespace: "cockpit",
    telegram,
    authorize: allowlist([ALICE.id]),
    ...options,
  });
  return { auth, telegram };
}

function messageUpdate(text, from = ALICE, messageId = 55) {
  return { message: { message_id: messageId, chat: { id: 4242, type: "private" }, from, text } };
}

test("the start handler confirms, replies, and tidies up after itself", async () => {
  const { auth, telegram } = setup();
  const handle = createStartHandler(auth);
  const { token } = await auth.beginLogin();

  assert.equal(await handle(messageUpdate(`/start cockpit_${token}`)), true);

  const sent = telegram.calls.find((call) => call.method === "sendMessage");
  assert.match(sent.payload.text, /signed in/i);
  assert.ok(telegram.calls.some((call) => call.method === "deleteMessage" && call.payload.message_id === 55));
});

test("the start handler ignores everything that isn't a sign-in for this app", async () => {
  const { auth, telegram } = setup();
  const handle = createStartHandler(auth);

  for (const update of [
    messageUpdate("/start"),
    messageUpdate("hello"),
    messageUpdate("/start otherapp_0123456789abcdef0123456789abcdef"),
    messageUpdate("/start cockpit_not-a-token"),
    { message: { message_id: 1, chat: { id: 1 }, from: ALICE } }, // a photo, no text
    { callback_query: { data: "x" } },
    {},
  ]) {
    assert.equal(await handle(update), false);
  }
  assert.equal(telegram.calls.length, 0, "an unrelated message must not produce any API call");
});

test("a rejected scan gets told why, and the token stays usable", async () => {
  const { auth, telegram } = setup();
  const handle = createStartHandler(auth);
  const { token } = await auth.beginLogin();

  assert.equal(await handle(messageUpdate(`/start cockpit_${token}`, MALLORY)), true);
  const sent = telegram.calls.find((call) => call.method === "sendMessage");
  assert.match(sent.payload.text, /not authorized/i);

  assert.equal((await auth.store.get(token, "cockpit")).status, "pending");
});

test("the success message says what is being signed into", async () => {
  const { auth, telegram } = setup();
  const handle = createStartHandler(auth);
  const request = makeRequest("https://cockpit.example/auth/login", {
    headers: { "CF-Connecting-IP": "203.0.113.7", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) Chrome/120.0" },
  });
  const { token } = await auth.beginLogin({ request });

  await handle(messageUpdate(`/start cockpit_${token}`));
  const text = telegram.calls.find((call) => call.method === "sendMessage").payload.text;
  assert.match(text, /https:\/\/cockpit\.example/);
  assert.match(text, /Chrome on macOS/);
  assert.match(text, /203\.0\.113\.7/);
  assert.match(text, /wasn't you/i);
});

test("client context can be suppressed", async () => {
  const { auth, telegram } = setup();
  const handle = createStartHandler(auth, { showClientContext: false });
  const { token } = await auth.beginLogin({ request: makeRequest("https://cockpit.example/", { headers: { "CF-Connecting-IP": "203.0.113.7" } }) });

  await handle(messageUpdate(`/start cockpit_${token}`));
  assert.equal(/203\.0\.113\.7/.test(telegram.calls.find((c) => c.method === "sendMessage").payload.text), false);
});

test("a failed message delete never fails the sign-in", async () => {
  const { auth, telegram } = setup();
  telegram.deleteMessage = async () => {
    throw new Error("message can't be deleted");
  };
  const handle = createStartHandler(auth);
  const { token } = await auth.beginLogin();

  assert.equal(await handle(messageUpdate(`/start cockpit_${token}`)), true);
  assert.equal((await auth.store.get(token, "cockpit")).status, "confirmed");
});

test("onSignIn fires only on success", async () => {
  const { auth } = setup();
  const signedIn = [];
  const handle = createStartHandler(auth, { onSignIn: (user) => signedIn.push(user.id) });

  const { token } = await auth.beginLogin();
  await handle(messageUpdate(`/start cockpit_${token}`, MALLORY));
  assert.deepEqual(signedIn, []);

  await handle(messageUpdate(`/start cockpit_${token}`, ALICE));
  assert.deepEqual(signedIn, [ALICE.id]);
});

test("the webhook handler checks Telegram's secret token", async () => {
  const { auth } = setup();
  const handle = createWebhookHandler(auth, { secretToken: "s3cret" });
  const { token } = await auth.beginLogin();

  const body = JSON.stringify(messageUpdate(`/start cockpit_${token}`));
  const post = (headers) => new Request("https://bot.example/webhook", { method: "POST", headers, body });

  assert.equal((await handle(post({}))).status, 403);
  assert.equal((await handle(post({ "X-Telegram-Bot-Api-Secret-Token": "wrong" }))).status, 403);
  assert.equal((await auth.store.get(token, "cockpit")).status, "pending");

  assert.equal((await handle(post({ "X-Telegram-Bot-Api-Secret-Token": "s3cret" }))).status, 200);
  assert.equal((await auth.store.get(token, "cockpit")).status, "confirmed");
});

test("the webhook handler acks anything Telegram sends, so nothing gets retried forever", async () => {
  const { auth } = setup();
  const unhandled = [];
  const handle = createWebhookHandler(auth, { onUnhandled: (update) => unhandled.push(update) });

  assert.equal((await handle(new Request("https://bot.example/webhook", { method: "POST", body: "{}" }))).status, 200);
  assert.equal((await handle(new Request("https://bot.example/webhook", { method: "POST", body: "not json" }))).status, 400);
  assert.equal((await handle(new Request("https://bot.example/webhook", { method: "GET" }))).status, 405);
  assert.equal(unhandled.length, 1);
});

test("a bring-your-own client only needs call()", async () => {
  const calls = [];
  const minimal = {
    async call(method, payload) {
      calls.push(method);
      return { ok: true, result: { status: "member", message_id: 1 } };
    },
  };
  const { auth } = setup({ telegram: minimal, botToken: "123:TEST" });
  const handle = createStartHandler(auth, { telegram: minimal });
  const { token } = await auth.beginLogin();

  assert.equal(await handle(messageUpdate(`/start cockpit_${token}`)), true);
  assert.deepEqual(calls, ["sendMessage", "deleteMessage"]);
});
