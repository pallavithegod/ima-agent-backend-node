import test from "node:test";
import assert from "node:assert/strict";
import { hashPassword, verifyPassword } from "../src/password.js";

test("password hashes verify without storing plaintext", () => {
  const stored = hashPassword("correct-horse-battery-staple");
  assert.equal(verifyPassword("correct-horse-battery-staple", stored), true);
  assert.equal(verifyPassword("wrong-password", stored), false);
  assert.equal(stored.includes("correct-horse"), false);
});

