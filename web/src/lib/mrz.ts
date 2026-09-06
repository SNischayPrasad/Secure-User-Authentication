/**
 * Machine-readable zone encoding, following the ICAO 9303 TD3 layout that passports use.
 *
 * The strip on the credential card is not a texture: it is a real two-line, 44-column MRZ
 * whose check digits are computed with the ICAO 7-3-1 weighting. Feeding these lines to any
 * MRZ parser yields the values shown in the card's own fields, which is the point — the card
 * says the same thing to a person and to a machine.
 */

export const MRZ_WIDTH = 44;

/** Characters an MRZ may contain. Everything else is folded to the filler '<'. */
function sanitise(input: string): string {
  return input
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "<")
    .replace(/^<+|<+$/g, "");
}

/** Pads (or truncates) to an exact column count using the MRZ filler character. */
function fit(value: string, width: number): string {
  return value.length >= width ? value.slice(0, width) : value + "<".repeat(width - value.length);
}

/** ICAO 9303 numeric value of an MRZ character: digits are themselves, A-Z are 10-35, '<' is 0. */
function charValue(ch: string): number {
  if (ch >= "0" && ch <= "9") return ch.charCodeAt(0) - 48;
  if (ch >= "A" && ch <= "Z") return ch.charCodeAt(0) - 55;
  return 0;
}

/**
 * ICAO 9303 check digit: each character is weighted by a repeating 7-3-1 cycle and the
 * weighted sum is taken modulo 10.
 */
export function checkDigit(input: string): string {
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < input.length; i += 1) {
    sum += charValue(input.charAt(i)) * (weights[i % 3] as number);
  }
  return String(sum % 10);
}

/** Formats an epoch-milliseconds timestamp as the YYMMDD form an MRZ date field uses. */
function mrzDate(epochMs: number): string {
  const d = new Date(epochMs);
  const yy = String(d.getUTCFullYear() % 100).padStart(2, "0");
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${yy}${mm}${dd}`;
}

/** Fixed three-letter role codes, so the nationality-equivalent field stays a stable width. */
const ROLE_CODES: Record<string, string> = { user: "USR", admin: "ADM" };

export type MrzSubject = {
  name: string;
  email: string;
  userId: string;
  role: string;
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
};

/**
 * The signed-out strip. An anonymous caller genuinely has no credential to encode, so the
 * document says exactly that rather than showing plausible-looking filler.
 */
export function anonymousMrz(): [string, string] {
  const line1 = fit("AC<SUAANONYMOUS<<NOT<ISSUED", MRZ_WIDTH);
  const body = fit("000000000", 9) + "0" + "SUA" + "000000" + "0" + "X" + "000000" + "0";
  const line2 = fit(body + "<".repeat(14) + "0", MRZ_WIDTH - 1);
  return [line1, line2 + checkDigit(line2)];
}

/**
 * Encodes a live credential. The identifier field carries the user id, the "nationality"
 * field carries the role, the date fields carry issue and expiry, and the optional-data
 * field carries the session id — so revoking that session provably changes the strip.
 */
export function credentialMrz(subject: MrzSubject): [string, string] {
  // MRZ name order is surname first, then given names, separated by a double filler.
  const parts = sanitise(subject.name).split("<").filter(Boolean);
  const family = parts.length > 1 ? (parts[parts.length - 1] as string) : (parts[0] ?? "HOLDER");
  const given = parts.length > 1 ? parts.slice(0, -1) : [];
  const nameField = given.length ? `${family}<<${given.join("<")}` : family;
  const line1 = fit(`AC<SUA${nameField}`, MRZ_WIDTH);

  const idField = fit(sanitise(subject.userId).replace(/^USR</, ""), 9);
  const idCheck = checkDigit(idField);

  // Roles get a stable three-letter code so the field is fixed-width and readable.
  const role = fit(ROLE_CODES[subject.role.toLowerCase()] ?? "GEN", 3);

  const issued = mrzDate(subject.issuedAt);
  const issuedCheck = checkDigit(issued);

  const expires = mrzDate(subject.expiresAt);
  const expiresCheck = checkDigit(expires);

  const holderMark = subject.email.includes("@") ? "H" : "<";

  const optional = fit(sanitise(subject.sessionId).replace(/^SES</, ""), 14);
  const optionalCheck = checkDigit(optional);

  const composite =
    idField + idCheck + issued + issuedCheck + expires + expiresCheck + optional + optionalCheck;

  const line2 = fit(
    idField +
      idCheck +
      role +
      issued +
      issuedCheck +
      holderMark +
      expires +
      expiresCheck +
      optional +
      optionalCheck +
      checkDigit(composite),
    MRZ_WIDTH,
  );

  return [line1, line2];
}

/**
 * Splits a line into runs of real characters and runs of filler so the filler can be dimmed.
 * Keeping the filler visible but quiet is what makes the strip read as a document rather
 * than as a random string.
 */
export function splitFiller(line: string): Array<{ text: string; filler: boolean }> {
  const parts: Array<{ text: string; filler: boolean }> = [];
  let buffer = "";
  let filler = line.startsWith("<");
  for (const ch of line) {
    const isFiller = ch === "<";
    if (isFiller !== filler) {
      if (buffer) parts.push({ text: buffer, filler });
      buffer = "";
      filler = isFiller;
    }
    buffer += ch;
  }
  if (buffer) parts.push({ text: buffer, filler });
  return parts;
}
