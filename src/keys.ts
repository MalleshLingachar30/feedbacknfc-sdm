const DEV_FIXTURE_MASTER_KEYS: Record<number, string> = {
  1: "000102030405060708090A0B0C0D0E0F",
  2: "101112131415161718191A1B1C1D1E1F",
  3: "202122232425262728292A2B2C2D2E2F"
};

export function getMasterKey(version: number) {
  const envKey = process.env[`SDM_MASTER_KEY_V${version}`];
  const fallback =
    process.env.NODE_ENV !== "production"
      ? DEV_FIXTURE_MASTER_KEYS[version]
      : undefined;
  const keyHex = envKey ?? fallback;

  if (!keyHex) {
    throw new Error(`Master key version ${version} is not configured.`);
  }

  const key = Buffer.from(keyHex, "hex");

  if (key.length !== 16) {
    throw new Error(`Master key version ${version} must be 16 bytes.`);
  }

  return key;
}

export function getDevFixtureMasterKeyHex() {
  return DEV_FIXTURE_MASTER_KEYS[1];
}
