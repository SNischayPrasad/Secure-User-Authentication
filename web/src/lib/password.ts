/**
 * A client-side mirror of the server's password policy.
 *
 * This exists only so the strength meter can respond as you type. The server re-runs the same
 * rules on every register and password change and is the sole authority — nothing here is
 * trusted, and bypassing it changes nothing about what the API will accept.
 */

const COMMON = [
  "password", "123456", "12345678", "123456789", "qwerty", "abc123", "monkey", "letmein",
  "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine", "master", "welcome",
  "shadow", "ashley", "football", "jesus", "michael", "ninja", "mustang", "password1",
  "qwertyuiop", "admin", "login", "starwars", "passw0rd", "changeme", "secret",
];

const SEQUENCES = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

export type Assessment = { ok: boolean; score: 0 | 1 | 2 | 3 | 4; issues: string[] };

function hasSequence(lower: string): boolean {
  for (const sequence of SEQUENCES) {
    for (let i = 0; i + 4 <= sequence.length; i += 1) {
      const run = sequence.slice(i, i + 4);
      if (lower.includes(run) || lower.includes([...run].reverse().join(""))) return true;
    }
  }
  return false;
}

/** Applies the policy and returns user-facing sentences describing anything still missing. */
export function assessPassword(
  plain: string,
  context: { email?: string; name?: string } = {},
): Assessment {
  const issues: string[] = [];
  const lower = plain.toLowerCase();

  if (plain.length < 12) issues.push("Use at least 12 characters.");
  if (plain.length > 200) issues.push("Use no more than 200 characters.");

  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(plain)).length;
  if (classes < 3) {
    issues.push("Mix at least three of: lower case, upper case, digits, symbols.");
  }

  const local = context.email?.split("@")[0]?.toLowerCase() ?? "";
  if (local.length >= 4 && lower.includes(local)) {
    issues.push("Do not include your email address.");
  }

  const name = context.name?.toLowerCase().trim() ?? "";
  if (name.length >= 4 && lower.includes(name)) {
    issues.push("Do not include your name.");
  }

  if (COMMON.some((entry) => lower === entry || lower.includes(entry))) {
    issues.push("This is a commonly used password. Choose something less predictable.");
  }

  if (hasSequence(lower)) {
    issues.push("Avoid runs of keyboard or alphabet order.");
  }

  const ok = issues.length === 0;

  let score = 0;
  if (plain.length >= 8) score += 1;
  if (plain.length >= 16) score += 1;
  if (classes >= 3) score += 1;
  if (plain.length >= 20 || (classes === 4 && plain.length >= 14)) score += 1;
  if (!ok) score = Math.min(score, 2);
  if (!plain) score = 0;

  return { ok, score: Math.max(0, Math.min(4, score)) as 0 | 1 | 2 | 3 | 4, issues };
}

export const STRENGTH_LABEL = ["Empty", "Too weak", "Weak", "Acceptable", "Strong"] as const;
export const STRENGTH_COLOUR = [
  "var(--rule-soft)",
  "var(--void)",
  "var(--void)",
  "var(--foil)",
  "var(--verified)",
] as const;
