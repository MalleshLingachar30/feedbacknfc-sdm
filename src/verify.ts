import crypto from "node:crypto";
import { aesCmac } from "./cmac.js";
import { deriveTagKeys } from "./diversify.js";
import { getMasterKey } from "./keys.js";
import { decryptPiccData, buildPiccPlaintext } from "./picc.js";

export type TapRejection =
  | "invalid_cmac"
  | "invalid_picc_format"
  | "missing_params"
  | "crypto_error";

export type VerifySuccess = {
  ok: true;
  tagUid: string;
  counter: number;
  keyVersion: number;
};

export type VerifyFailure = {
  ok: false;
  reason: TapRejection;
};

function constantTimeEqual(a: Buffer, b: Buffer) {
  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}

export async function verifySdm(params: {
  piccData?: string | null;
  cmac?: string | null;
  keyVersion?: number;
}): Promise<VerifySuccess | VerifyFailure> {
  if (!params.piccData || !params.cmac) {
    return { ok: false, reason: "missing_params" };
  }

  try {
    const keyVersion = params.keyVersion ?? 1;
    const masterKey = getMasterKey(keyVersion);

    let decrypted;

    try {
      decrypted = decryptPiccData(masterKey, params.piccData);
    } catch {
      return { ok: false, reason: "invalid_picc_format" };
    }

    const uidBuffer = Buffer.from(decrypted.tagUid, "hex");
    const { fileReadKey } = deriveTagKeys(masterKey, uidBuffer);
    const sessionVector = buildPiccPlaintext(uidBuffer, decrypted.counter);
    const sessionKey = aesCmac(fileReadKey, sessionVector);
    const expectedFullCmac = aesCmac(sessionKey, Buffer.from(params.piccData, "hex"));
    const provided = Buffer.from(params.cmac, "hex");

    if (!constantTimeEqual(expectedFullCmac.subarray(0, 8), provided.subarray(0, 8))) {
      return { ok: false, reason: "invalid_cmac" };
    }

    return {
      ok: true,
      tagUid: decrypted.tagUid,
      counter: decrypted.counter,
      keyVersion
    };
  } catch (error) {
    console.error("[sdm.verify] verification failed", error);
    return { ok: false, reason: "crypto_error" };
  }
}
