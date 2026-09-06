import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Crockford-style base32: 32 URL-safe characters with the look-alikes I, L, O and U removed.
 *
 * The size is exactly a power of two, so a random byte is reduced with a 5-bit mask instead of
 * `% 32` — uniform, free of modulo bias, and with no rejection loop (so id generation also runs
 * in constant time). Uppercase alphanumerics only, which keeps `_` out of the random segment so
 * `prefix_id` stays unambiguously splittable.
 */
const ID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Characters after the `prefix_`. 21 chars over a 32-char alphabet = 105 bits of entropy. */
const ID_LENGTH = 21;

/**
 * Generates a prefixed, URL-safe identifier: `prefix + "_" + 21 random characters`.
 * Backed by `crypto.randomBytes` (CSPRNG) rather than `Math.random`, because these ids are used
 * as session ids and audit ids where predictability would be exploitable.
 *
 * @param prefix short type tag, e.g. `"usr"`, `"ses"`, `"itm"`, `"req"`.
 */
export function newId(prefix: string): string {
  let id = "";
  for (const byte of randomBytes(ID_LENGTH)) {
    // `charAt` (unlike indexing) is typed as `string`, and the 5-bit mask is always in range.
    id += ID_ALPHABET.charAt(byte & 31);
  }
  return `${prefix}_${id}`;
}

/**
 * Produces an opaque high-entropy secret, base64url encoded so it is safe in cookies, headers
 * and URLs. Used for refresh tokens and CSRF tokens; the default 32 bytes is 256 bits.
 *
 * @param bytes number of random bytes to draw (default 32).
 */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/**
 * Returns the lowercase hex sha256 digest of a UTF-8 string. Refresh tokens are stored only as
 * this digest, so a leaked database still cannot be used to mint sessions.
 */
export function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Constant-time string comparison (used for CSRF double-submit and other secret comparisons).
 *
 * Both sides are hashed first so the digests are always 32 bytes: `timingSafeEqual` throws on
 * mismatched lengths, and comparing raw strings would leak the secret's length through that
 * throw and through early-exit timing.
 */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const digestA = createHash("sha256").update(a, "utf8").digest();
  const digestB = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(digestA, digestB);
}
