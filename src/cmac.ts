import crypto from "node:crypto";

const BLOCK_SIZE = 16;
const RB = 0x87;

function xorBuffers(a: Buffer, b: Buffer) {
  const result = Buffer.alloc(a.length);

  for (let index = 0; index < a.length; index += 1) {
    result[index] = a[index] ^ b[index];
  }

  return result;
}

function aes128EcbEncrypt(key: Buffer, block: Buffer) {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function leftShiftOne(buffer: Buffer) {
  const shifted = Buffer.alloc(BLOCK_SIZE);
  let carry = 0;

  for (let index = BLOCK_SIZE - 1; index >= 0; index -= 1) {
    const value = buffer[index];
    shifted[index] = ((value << 1) | carry) & 0xff;
    carry = value >> 7;
  }

  if (carry) {
    shifted[BLOCK_SIZE - 1] ^= RB;
  }

  return shifted;
}

function generateSubkeys(key: Buffer) {
  const zero = Buffer.alloc(BLOCK_SIZE, 0);
  const l = aes128EcbEncrypt(key, zero);
  const k1 = leftShiftOne(l);
  const k2 = leftShiftOne(k1);
  return { k1, k2 };
}

function splitBlocks(message: Buffer) {
  if (message.length === 0) {
    return [Buffer.alloc(0)];
  }

  return Array.from(
    { length: Math.ceil(message.length / BLOCK_SIZE) },
    (_, index) => message.subarray(index * BLOCK_SIZE, (index + 1) * BLOCK_SIZE)
  );
}

export function aesCmac(key: Buffer, message: Buffer) {
  if (key.length !== BLOCK_SIZE) {
    throw new Error("AES-CMAC requires a 16-byte AES-128 key.");
  }

  const { k1, k2 } = generateSubkeys(key);
  const blocks = splitBlocks(message);
  const lastBlock = blocks[blocks.length - 1];
  const isComplete = message.length !== 0 && message.length % BLOCK_SIZE === 0;

  const finalBlock = isComplete
    ? xorBuffers(lastBlock, k1)
    : xorBuffers(
        Buffer.concat([
          lastBlock,
          Buffer.from([0x80]),
          Buffer.alloc(BLOCK_SIZE - lastBlock.length - 1, 0)
        ]),
        k2
      );

  let chained = Buffer.alloc(BLOCK_SIZE, 0);

  for (const block of blocks.slice(0, -1)) {
    chained = aes128EcbEncrypt(key, xorBuffers(chained, block));
  }

  return aes128EcbEncrypt(key, xorBuffers(chained, finalBlock));
}
