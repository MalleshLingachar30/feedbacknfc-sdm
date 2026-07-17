import { aesCmac } from "./cmac.js";
import { deriveTagKeys } from "./diversify.js";
import { getMasterKey } from "./keys.js";
import { buildPiccPlaintext, encryptPiccData } from "./picc.js";

export function createDevTapPayload(params: {
  tagUid: string;
  counter: number;
  keyVersion?: number;
}) {
  const keyVersion = params.keyVersion ?? 1;
  const masterKey = getMasterKey(keyVersion);
  const uidBuffer = Buffer.from(params.tagUid, "hex");
  const encryptedPicc = encryptPiccData(masterKey, uidBuffer, params.counter);
  const { fileReadKey } = deriveTagKeys(masterKey, uidBuffer);
  const sessionKey = aesCmac(fileReadKey, buildPiccPlaintext(uidBuffer, params.counter));
  const cmac = aesCmac(sessionKey, encryptedPicc).subarray(0, 8);

  return {
    piccData: encryptedPicc.toString("hex").toUpperCase(),
    cmac: cmac.toString("hex").toUpperCase(),
    counter: params.counter,
    tagUid: params.tagUid.toUpperCase(),
    keyVersion
  };
}
