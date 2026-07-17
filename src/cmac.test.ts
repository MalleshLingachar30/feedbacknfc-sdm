import assert from "node:assert/strict";
import test from "node:test";
import { aesCmac } from "./cmac.js";

const key = Buffer.from("2b7e151628aed2a6abf7158809cf4f3c", "hex");

test("aesCmac matches RFC 4493 empty message vector", () => {
  const mac = aesCmac(key, Buffer.alloc(0));
  assert.equal(mac.toString("hex"), "bb1d6929e95937287fa37d129b756746");
});

test("aesCmac matches RFC 4493 single-block vector", () => {
  const message = Buffer.from("6bc1bee22e409f96e93d7e117393172a", "hex");
  const mac = aesCmac(key, message);
  assert.equal(mac.toString("hex"), "070a16b46b4d4144f79bdd9dd04a287c");
});

test("aesCmac matches RFC 4493 multi-block vector", () => {
  const message = Buffer.from(
    "6bc1bee22e409f96e93d7e117393172a" +
      "ae2d8a571e03ac9c9eb76fac45af8e51" +
      "30c81c46a35ce411",
    "hex"
  );
  const mac = aesCmac(key, message);
  assert.equal(mac.toString("hex"), "dfa66747de9ae63030ca32611497c827");
});
