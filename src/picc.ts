import crypto from "node:crypto";

function aes128CbcDecrypt(key: Buffer, encrypted: Buffer) {
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, Buffer.alloc(16, 0));
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

function aes128CbcEncrypt(key: Buffer, plain: Buffer) {
  const cipher = crypto.createCipheriv("aes-128-cbc", key, Buffer.alloc(16, 0));
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(plain), cipher.final()]);
}

export function decodeCounter(counterBytes: Buffer) {
  return (counterBytes[0] << 16) | (counterBytes[1] << 8) | counterBytes[2];
}

export function encodeCounter(counter: number) {
  if (counter < 0 || counter > 0xffffff) {
    throw new Error("Tap counter must fit inside 24 bits.");
  }

  return Buffer.from([
    (counter >> 16) & 0xff,
    (counter >> 8) & 0xff,
    counter & 0xff
  ]);
}

export function buildPiccPlaintext(tagUid: Buffer, counter: number) {
  if (tagUid.length !== 7) {
    throw new Error("Tag UID must be 7 bytes.");
  }

  return Buffer.concat([
    Buffer.from([0xc7]),
    tagUid,
    encodeCounter(counter),
    Buffer.alloc(5, 0)
  ]);
}

export function encryptPiccData(metaReadKey: Buffer, tagUid: Buffer, counter: number) {
  const plaintext = buildPiccPlaintext(tagUid, counter);
  return aes128CbcEncrypt(metaReadKey, plaintext);
}

export function decryptPiccData(metaReadKey: Buffer, piccDataHex: string) {
  const encrypted = Buffer.from(piccDataHex, "hex");

  if (encrypted.length !== 16) {
    throw new Error("Encrypted PICC data must be 16 bytes.");
  }

  const decrypted = aes128CbcDecrypt(metaReadKey, encrypted);

  if (decrypted[0] !== 0xc7) {
    throw new Error("Invalid PICC marker byte.");
  }

  return {
    tagUid: decrypted.subarray(1, 8).toString("hex").toUpperCase(),
    counter: decodeCounter(decrypted.subarray(8, 11))
  };
}
