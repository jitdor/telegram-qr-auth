import test from "node:test";
import assert from "node:assert/strict";

import { anyUser, chatMember, chatMemberOfAny, chatMemberOfAll, allowlist, denylist, every, some, normalize, parseIdList, splitList } from "../src/gates.js";
import { makeFakeTelegram, ALICE, MALLORY } from "./helpers.mjs";

const CHAT_ID = "-1001234567890";
const ctx = (telegram) => ({ telegram, stage: "confirm" });

test("anyUser lets everyone through", async () => {
  assert.equal(await anyUser()(MALLORY, ctx(null)), true);
});

test("chatMember follows the chat", async () => {
  const telegram = makeFakeTelegram({ members: [ALICE.id] });
  const gate = chatMember({ chatId: CHAT_ID, onError: () => {} });

  assert.equal(await gate(ALICE, ctx(telegram)), true);
  assert.deepEqual(await gate(MALLORY, ctx(telegram)), { ok: false, reason: "not_a_member" });

  telegram.memberIds.add(MALLORY.id);
  assert.equal(await gate(MALLORY, ctx(telegram)), true);
});

test("chatMember fails closed when Telegram errors", async () => {
  const broken = {
    async getChatMember() {
      throw new Error("502 Bad Gateway");
    },
  };
  const errors = [];
  const gate = chatMember({ chatId: CHAT_ID, onError: (err) => errors.push(err) });
  assert.deepEqual(await gate(ALICE, ctx(broken)), { ok: false, reason: "not_a_member" });
  assert.equal(errors.length, 1);
});

test("chatMember treats left and kicked as out", async () => {
  const telegram = makeFakeTelegram({ members: [ALICE.id], status: "kicked" });
  const gate = chatMember({ chatId: CHAT_ID, onError: () => {} });
  assert.deepEqual(await gate(ALICE, ctx(telegram)), { ok: false, reason: "not_a_member" });
});

test("chatMember can be narrowed to admins", async () => {
  const telegram = makeFakeTelegram({ members: [ALICE.id], status: "member" });
  const adminsOnly = chatMember({ chatId: CHAT_ID, statuses: new Set(["creator", "administrator"]), onError: () => {} });
  assert.deepEqual(await adminsOnly(ALICE, ctx(telegram)), { ok: false, reason: "not_a_member" });

  const asAdmin = makeFakeTelegram({ members: [ALICE.id], status: "administrator" });
  assert.equal(await adminsOnly(ALICE, ctx(asAdmin)), true);
});

test("chatMember insists on a chatId and on a client", async () => {
  assert.throws(() => chatMember({}), /chatId/);
  await assert.rejects(() => chatMember({ chatId: CHAT_ID })(ALICE, { stage: "confirm" }), /Telegram client/);
});

test("chatMemberOfAny: in at least one of several groups", async () => {
  const telegram = makeFakeTelegram({ members: [] });
  // The fake reports membership per user, not per chat, so drive it by user instead: Alice is in
  // the chats, Mallory is in none.
  telegram.memberIds.add(ALICE.id);
  const gate = chatMemberOfAny("-100111,-100222", { onError: () => {} });

  assert.equal(await gate(ALICE, ctx(telegram)), true);
  assert.deepEqual(await gate(MALLORY, ctx(telegram)), { ok: false, reason: "not_a_member" });

  // Comes straight from an env var, and an array works too.
  assert.equal(await chatMemberOfAny(["-100111"], { onError: () => {} })(ALICE, ctx(telegram)), true);
  assert.throws(() => chatMemberOfAny(""), /at least one chat id/);
});

test("chatMemberOfAny stops asking Telegram once one chat says yes", async () => {
  const telegram = makeFakeTelegram({ members: [ALICE.id] });
  await chatMemberOfAny("-100111,-100222,-100333", { onError: () => {} })(ALICE, ctx(telegram));
  assert.equal(telegram.calls.length, 1);
});

test("chatMemberOfAll: in every group, short-circuiting on the first miss", async () => {
  const telegram = makeFakeTelegram({ members: [ALICE.id] });
  const gate = chatMemberOfAll("-100111,-100222", { onError: () => {} });

  assert.equal(await gate(ALICE, ctx(telegram)), true);
  assert.equal(telegram.calls.length, 2, "every chat is checked when they all pass");

  telegram.calls.length = 0;
  assert.deepEqual(await gate(MALLORY, ctx(telegram)), { ok: false, reason: "not_a_member" });
  assert.equal(telegram.calls.length, 1, "a miss stops the remaining calls");
  assert.throws(() => chatMemberOfAll([]), /at least one chat id/);
});

test("allowlist and denylist", async () => {
  const allowed = allowlist([ALICE.id]);
  assert.equal(await allowed(ALICE, ctx(null)), true);
  assert.deepEqual(await allowed(MALLORY, ctx(null)), { ok: false, reason: "not_allowlisted" });

  const denied = denylist(`${MALLORY.id}`);
  assert.equal(await denied(ALICE, ctx(null)), true);
  assert.deepEqual(await denied(MALLORY, ctx(null)), { ok: false, reason: "denied" });
});

test("every short-circuits and keeps the failing reason", async () => {
  const calls = [];
  const record = (name, result) => async () => {
    calls.push(name);
    return result;
  };
  const gate = every(record("first", true), record("second", { ok: false, reason: "nope" }), record("third", true));
  assert.deepEqual(await gate(ALICE, ctx(null)), { ok: false, reason: "nope" });
  assert.deepEqual(calls, ["first", "second"]);
});

test("some passes on the first success and reports the last failure otherwise", async () => {
  assert.equal(await some(allowlist([]), allowlist([ALICE.id]))(ALICE, ctx(null)), true);
  assert.deepEqual(await some(allowlist([]), allowlist([]))(ALICE, ctx(null)), { ok: false, reason: "not_allowlisted" });
});

test("gates compose: in the group AND on the shortlist", async () => {
  const telegram = makeFakeTelegram({ members: [ALICE.id, MALLORY.id] });
  const gate = every(chatMember({ chatId: CHAT_ID, onError: () => {} }), allowlist([ALICE.id]));
  assert.equal(await gate(ALICE, ctx(telegram)), true);
  assert.deepEqual(await gate(MALLORY, ctx(telegram)), { ok: false, reason: "not_allowlisted" });
});

test("normalize accepts every shape a gate may return", () => {
  assert.deepEqual(normalize(true), { ok: true });
  assert.deepEqual(normalize(false), { ok: false, reason: "denied" });
  assert.deepEqual(normalize(undefined), { ok: false, reason: "denied" });
  assert.deepEqual(normalize({ ok: false, reason: "why" }), { ok: false, reason: "why" });
  assert.deepEqual(normalize({ ok: true }), { ok: true, reason: "denied" });
});

test("splitList keeps chat ids as strings, since that's how Telegram wants them back", () => {
  assert.deepEqual(splitList("-1001234567890, -1009876543210"), ["-1001234567890", "-1009876543210"]);
  assert.deepEqual(splitList(["@publicchannel", " -100111 "]), ["@publicchannel", "-100111"]);
  assert.deepEqual(splitList(""), []);
  assert.deepEqual(splitList(undefined), []);
});

test("parseIdList takes the shapes an env var actually arrives in", () => {
  assert.deepEqual(parseIdList("39644372, 12345"), [39644372, 12345]);
  assert.deepEqual(parseIdList(["39644372", 12345]), [39644372, 12345]);
  assert.deepEqual(parseIdList(""), []);
  assert.deepEqual(parseIdList(undefined), []);
  assert.deepEqual(parseIdList("39644372, not-a-number"), [39644372]);
});
