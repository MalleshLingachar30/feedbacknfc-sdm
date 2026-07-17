import { aesCmac } from "./cmac.js";

export function deriveTagKeys(masterKey: Buffer, tagUid: Buffer) {
  if (masterKey.length !== 16) {
    throw new Error("Master key must be 16 bytes.");
  }

  if (tagUid.length !== 7) {
    throw new Error("Tag UID must be 7 bytes.");
  }

  const metaSeed = Buffer.concat([Buffer.from([0x01]), tagUid, Buffer.alloc(8, 0)]);
  const fileSeed = Buffer.concat([Buffer.from([0x02]), tagUid, Buffer.alloc(8, 0)]);

  return {
    metaReadKey: aesCmac(masterKey, metaSeed),
    fileReadKey: aesCmac(masterKey, fileSeed)
  };
}
