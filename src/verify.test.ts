import assert from "node:assert/strict";
import test from "node:test";
import { createDevTapPayload } from "./dev-fixtures.js";
import { getDevFixtureMasterKeyHex } from "./keys.js";
import { verifySdm } from "./verify.js";

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

test("verifySdm rejects missing parameters", async () => {
  const result = await verifySdm({ piccData: null, cmac: null });
  assert.deepEqual(result, { ok: false, reason: "missing_params" });
});
