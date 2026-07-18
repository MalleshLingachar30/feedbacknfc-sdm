import assert from "node:assert/strict";
import test from "node:test";
import { createDevTapPayload } from "./dev-fixtures.js";
import { getDevFixtureMasterKeyHex } from "./keys.js";
import { verifySdm, verifySdmCounter } from "./verify.js";

test("verifySdm accepts a valid development payload", async () => {
  process.env.SDM_MASTER_KEY_V1 = getDevFixtureMasterKeyHex();

  const payload = createDevTapPayload({
    tagUid: "04A1B2C3D4E5F6",
    counter: 19
  });

  const result = await verifySdm(payload);

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.tagUid, "04A1B2C3D4E5F6");
    assert.equal(result.counter, 19);
  }
});

test("verifySdm rejects a tampered CMAC", async () => {
  process.env.SDM_MASTER_KEY_V1 = getDevFixtureMasterKeyHex();

  const payload = createDevTapPayload({
    tagUid: "04A1B2C3D4E5F6",
    counter: 20
  });

  const result = await verifySdm({
    ...payload,
    cmac: payload.cmac.replace(/.$/, payload.cmac.endsWith("0") ? "1" : "0")
  });

  assert.deepEqual(result, { ok: false, reason: "invalid_cmac" });
});

test("verifySdm rejects a replayed counter at or below last seen", async () => {
  process.env.SDM_MASTER_KEY_V1 = getDevFixtureMasterKeyHex();

  const repeatedPayload = createDevTapPayload({
    tagUid: "04A1B2C3D4E5F6",
    counter: 20
  });
  const olderPayload = createDevTapPayload({
    tagUid: "04A1B2C3D4E5F6",
    counter: 19
  });

  assert.deepEqual(await verifySdm({ ...repeatedPayload, lastSeenCounter: 20 }), {
    ok: false,
    reason: "replayed_counter"
  });
  assert.deepEqual(await verifySdm({ ...olderPayload, lastSeenCounter: 20 }), {
    ok: false,
    reason: "replayed_counter"
  });
});

test("verifySdm accepts a fresh counter above last seen", async () => {
  process.env.SDM_MASTER_KEY_V1 = getDevFixtureMasterKeyHex();

  const payload = createDevTapPayload({
    tagUid: "04A1B2C3D4E5F6",
    counter: 21
  });

  const result = await verifySdm({ ...payload, lastSeenCounter: 20 });

  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.counter, 21);
  }
});

test("verifySdmCounter returns a replay rejection with counter context", () => {
  assert.deepEqual(verifySdmCounter({ counter: 7, lastSeenCounter: 7 }), {
    ok: false,
    reason: "replayed_counter",
    counter: 7,
    lastSeenCounter: 7
  });
});

test("verifySdm rejects missing parameters", async () => {
  const result = await verifySdm({ piccData: null, cmac: null });
  assert.deepEqual(result, { ok: false, reason: "missing_params" });
});
