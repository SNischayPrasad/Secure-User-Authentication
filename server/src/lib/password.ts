import { hash, verify, Algorithm } from "@node-rs/argon2";

/**
 * Argon2id work factors applied to every password we store.
 * These are the OWASP Password Storage Cheat Sheet minimums (19 MiB, 2 passes, 1 lane);
 * exported so a test can assert the cost is never quietly lowered.
 */
export const ARGON2_OPTIONS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
};

/** Minimum accepted password length; a long passphrase beats a short complex string. */
export const PASSWORD_MIN_LENGTH = 12;

/** Maximum accepted password length, so a huge body cannot turn Argon2 into a CPU denial of service. */
export const PASSWORD_MAX_LENGTH = 200;

/** Strength band returned by {@link assessPassword}: 0 is unusable, 4 is strong. */
export type PasswordScore = 0 | 1 | 2 | 3 | 4;

/** Result of the password policy check, safe to serialise straight to the client. */
export type PasswordAssessment = {
  ok: boolean;
  score: PasswordScore;
  issues: string[];
};

/**
 * Passwords at the top of every breach corpus. The candidate password is normalised and
 * de-leeted before lookup, so `P@ssw0rd!` is caught by the entry `password`.
 */
const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  "123456",
  "1234567",
  "12345678",
  "123456789",
  "1234567890",
  "12345",
  "111111",
  "000000",
  "121212",
  "123123",
  "654321",
  "987654321",
  "555555",
  "666666",
  "696969",
  "abc123",
  "a1b2c3",
  "password",
  "password1",
  "passw0rd",
  "letmein",
  "welcome",
  "welcome1",
  "admin",
  "admin123",
  "administrator",
  "root",
  "toor",
  "guest",
  "login",
  "changeme",
  "secret",
  "qwerty",
  "qwerty123",
  "qwertyuiop",
  "qwertz",
  "azerty",
  "asdfgh",
  "asdfghjkl",
  "zxcvbn",
  "zxcvbnm",
  "qazwsx",
  "1qaz2wsx",
  "1q2w3e4r",
  "iloveyou",
  "trustno1",
  "monkey",
  "dragon",
  "shadow",
  "master",
  "killer",
  "hunter",
  "ranger",
  "buster",
  "harley",
  "batman",
  "superman",
  "starwars",
  "pokemon",
  "football",
  "baseball",
  "soccer",
  "hockey",
  "sunshine",
  "princess",
  "flower",
  "pepper",
  "cheese",
  "computer",
  "internet",
  "whatever",
  "freedom",
  "summer",
  "winter",
  "google",
  "michael",
  "jennifer",
  "jessica",
  "charlie",
  "daniel",
  "andrew",
  "george",
  "access",
  "ninja",
  "test123",
]);

/**
 * Keyboard walks and counting runs rejected wherever they appear inside a password,
 * because `Aa!123456789` is one dictionary rule away from free despite passing the class check.
 */
const WEAK_FRAGMENTS: readonly string[] = [
  "123456",
  "1234567",
  "12345678",
  "123456789",
  "1234567890",
  "098765",
  "87654321",
  "abcdef",
  "abcdefg",
  "qwerty",
  "qwertz",
  "azerty",
  "asdfgh",
  "zxcvbn",
  "qazwsx",
  "1qaz2wsx",
  "1q2w3e4r",
  "password",
  "letmein",
  "iloveyou",
  "admin123",
  "welcome1",
  "trustno1",
  "changeme",
];

/** Fixed input behind {@link getDummyHash}; it is never a credential, only timing ballast. */
const DUMMY_PASSWORD = "argon2id-timing-ballast-not-a-credential-2f7c1ab9";

/** Memoised promise so the dummy hash is derived at most once per process. */
let dummyHashPromise: Promise<string> | null = null;

/**
 * Hashes a plaintext password with Argon2id and returns the encoded PHC string.
 * Algorithm, cost parameters and a per-password salt all travel inside that string,
 * so there is no separate salt column to get out of step with the hash.
 */
export async function hashPassword(plain: string): Promise<string> {
  return hash(plain, ARGON2_OPTIONS);
}

/**
 * Checks a plaintext password against an encoded Argon2 hash.
 * Returns false instead of throwing on a malformed or unknown hash, so a corrupt row
 * degrades to "wrong password" rather than a 500 that distinguishes one account from another.
 */
export async function verifyPassword(encodedHash: string, plain: string): Promise<boolean> {
  if (typeof encodedHash !== "string" || !encodedHash.startsWith("$argon2")) return false;
  try {
    // Deliberately no options: the cost parameters are read from the encoded hash,
    // so hashes written under an older ARGON2_OPTIONS keep verifying after we raise it.
    return await verify(encodedHash, plain);
  } catch {
    return false;
  }
}

/**
 * Returns an Argon2id hash of a constant string, computed once and memoised.
 * Login verifies against it when the email is unknown, so an attacker cannot enumerate
 * accounts by timing the gap between "no such user" and "wrong password".
 */
export function getDummyHash(): Promise<string> {
  if (dummyHashPromise === null) {
    dummyHashPromise = hashPassword(DUMMY_PASSWORD).catch((err: unknown) => {
      dummyHashPromise = null; // let a later login retry instead of wedging the process
      throw err;
    });
  }
  return dummyHashPromise;
}

/**
 * Applies the password policy and returns user-facing issues plus a 0-4 strength score.
 * Strength is judged here rather than in zod so the API can report every reason at once,
 * and personal terms are rejected because they are the first guess in a targeted attack.
 */
export function assessPassword(
  plain: string,
  opts: { email?: string; name?: string },
): PasswordAssessment {
  const issues: string[] = [];
  const value = typeof plain === "string" ? plain : "";
  const lower = value.toLowerCase();
  const length = value.length;

  if (length < PASSWORD_MIN_LENGTH) {
    issues.push(`Use at least ${PASSWORD_MIN_LENGTH} characters.`);
  }
  if (length > PASSWORD_MAX_LENGTH) {
    issues.push(`Use at most ${PASSWORD_MAX_LENGTH} characters.`);
  }

  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasDigit = /[0-9]/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const classCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

  if (classCount < 3) {
    issues.push(
      "Mix at least three of these: lowercase letters, uppercase letters, numbers and symbols.",
    );
  }

  const localPart = opts.email?.split("@")[0]?.trim().toLowerCase() ?? "";
  if (localPart.length >= 4 && lower.includes(localPart)) {
    issues.push("Leave your email address out of the password.");
  }

  if (personalTerms(opts.name).some((term) => lower.includes(term))) {
    issues.push("Leave your name out of the password.");
  }

  if (isCommonPassword(lower)) {
    issues.push("This password appears in public breach lists. Pick one unrelated to it.");
  }

  if (containsWeakFragment(lower)) {
    issues.push("Avoid keyboard patterns and counting runs such as qwerty or 123456.");
  }

  if (hasSequentialRun(lower, 5)) {
    issues.push("Avoid five or more characters that run in order, such as abcde or 45678.");
  }

  if (hasRepeatedRun(value, 5)) {
    issues.push("Avoid repeating the same character five or more times in a row.");
  }

  const ok = issues.length === 0;
  return { ok, score: scorePassword(length, classCount, ok), issues };
}

/**
 * Scores length and character variety, then caps a failing password at 2 so the meter
 * can never read "strong" for something the policy is about to reject.
 */
function scorePassword(length: number, classCount: number, ok: boolean): PasswordScore {
  let lengthPoints = 0;
  if (length >= 12) lengthPoints = 1;
  if (length >= 16) lengthPoints = 2;
  if (length >= 20) lengthPoints = 3;

  let varietyPoints = 0;
  if (classCount >= 3) varietyPoints = 1;
  if (classCount >= 4) varietyPoints = 2;

  const raw = Math.min(4, lengthPoints + varietyPoints);
  const capped = ok ? raw : Math.min(raw, 2);
  return Math.max(0, capped) as PasswordScore;
}

/** Lowercase name terms worth blocking (whole name plus each word), ignoring anything under 4 characters. */
function personalTerms(name: string | undefined): string[] {
  const trimmed = name?.trim().toLowerCase() ?? "";
  if (trimmed.length === 0) return [];
  const terms = new Set<string>();
  for (const candidate of [trimmed, ...trimmed.split(/\s+/)]) {
    if (candidate.length >= 4) terms.add(candidate);
  }
  return [...terms];
}

/** Maps common leetspeak substitutions back to letters so `P@$$w0rd` is compared as `password`. */
function deLeet(value: string): string {
  return value
    .replace(/[@4]/g, "a")
    .replace(/[$5]/g, "s")
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/7/g, "t")
    .replace(/9/g, "g")
    .replace(/!/g, "i")
    .replace(/\+/g, "t");
}

/** Drops every character that is not an ASCII letter or digit. */
function stripNonAlnum(value: string): string {
  return value.replace(/[^a-z0-9]+/g, "");
}

/** Normalised forms of a password that the breach list and fragment list are checked against. */
function variants(lower: string): string[] {
  const deLeeted = deLeet(lower);
  return [...new Set([lower, deLeeted, stripNonAlnum(lower), stripNonAlnum(deLeeted)])];
}

/** True when the password, its de-leeted form, or its letter-bounded core is a known breached password. */
function isCommonPassword(lower: string): boolean {
  for (const candidate of variants(lower)) {
    if (COMMON_PASSWORDS.has(candidate)) return true;
    const core = candidate.replace(/^[^a-z]+/, "").replace(/[^a-z]+$/, "");
    if (core.length >= 4 && COMMON_PASSWORDS.has(core)) return true;
  }
  return false;
}

/** True when a keyboard walk or counting run appears anywhere inside the password. */
function containsWeakFragment(lower: string): boolean {
  for (const candidate of variants(lower)) {
    for (const fragment of WEAK_FRAGMENTS) {
      if (candidate.includes(fragment)) return true;
    }
  }
  return false;
}

/** True when `minLength` or more characters run consecutively up or down the code-point ladder. */
function hasSequentialRun(lower: string, minLength: number): boolean {
  let ascending = 1;
  let descending = 1;
  for (let i = 1; i < lower.length; i += 1) {
    const previous = lower.charCodeAt(i - 1);
    const current = lower.charCodeAt(i);
    ascending = current === previous + 1 ? ascending + 1 : 1;
    descending = current === previous - 1 ? descending + 1 : 1;
    if (ascending >= minLength || descending >= minLength) return true;
  }
  return false;
}

/** True when the same character repeats `minLength` or more times back to back. */
function hasRepeatedRun(value: string, minLength: number): boolean {
  let run = 1;
  for (let i = 1; i < value.length; i += 1) {
    run = value[i] === value[i - 1] ? run + 1 : 1;
    if (run >= minLength) return true;
  }
  return false;
}
