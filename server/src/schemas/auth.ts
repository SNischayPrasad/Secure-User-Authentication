import { z } from "zod";

/**
 * Request-body validation schemas (CONTRACT section 7).
 *
 * These schemas only police *shape* — length, type, format. Password *strength* is deliberately
 * NOT checked here: `assessPassword` in `lib/password.ts` returns rich, user-facing `issues`
 * that we surface as a `WEAK_PASSWORD` error, which zod's flat issue list cannot express as well.
 */

/**
 * Email address, normalised to trimmed + lowercase so that a single canonical form is stored,
 * compared and indexed — otherwise `Foo@x.com` and `foo@x.com` could become two accounts.
 */
export const emailSchema = z
  .string({ error: "Email is required." })
  .trim()
  .toLowerCase()
  .email("Enter a valid email address.")
  .max(254, "Email address must be 254 characters or fewer.");

/** Display name, trimmed; length-bounded so it cannot be used to bloat rows or break layouts. */
export const nameSchema = z
  .string({ error: "Name is required." })
  .trim()
  .min(2, "Name must be at least 2 characters.")
  .max(80, "Name must be 80 characters or fewer.");

/**
 * Raw password. Never trimmed — leading and trailing whitespace is part of the secret and
 * silently altering it would lock people out of accounts they typed correctly.
 * Upper bound guards the Argon2id hasher against absurdly long inputs.
 */
export const passwordSchema = z
  .string({ error: "Password is required." })
  .min(1, "Password is required.")
  .max(200, "Password must be 200 characters or fewer.");

/** Body for `POST /api/v1/auth/register`. */
export const registerSchema = z.object({
  name: nameSchema,
  email: emailSchema,
  password: passwordSchema,
});

/** Body for `POST /api/v1/auth/login`. */
export const loginSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

/** Body for `PATCH /api/v1/me`. */
export const updateProfileSchema = z.object({
  name: nameSchema,
});

/** Body for `POST /api/v1/me/password`; the current password is required so a stolen access token alone cannot change it. */
export const changePasswordSchema = z.object({
  currentPassword: passwordSchema,
  newPassword: passwordSchema,
});

/** Body for `POST /api/v1/vault` and `PATCH /api/v1/vault/:id` (use `.partial()` for the patch). */
export const vaultItemSchema = z.object({
  title: z
    .string({ error: "Title is required." })
    .trim()
    .min(1, "Title is required.")
    .max(120, "Title must be 120 characters or fewer."),
  body: z
    .string({ error: "Contents are required." })
    .trim()
    .min(1, "Body is required.")
    .max(4000, "Body must be 4000 characters or fewer."),
});

/** Route params carrying a resource id; bounded so no unbounded string reaches a query. */
export const idParamSchema = z.object({
  id: z
    .string()
    .min(3, "That identifier is not valid.")
    .max(64, "That identifier is not valid."),
});

/** Parsed body of a register request. */
export type RegisterInput = z.infer<typeof registerSchema>;
/** Parsed body of a login request. */
export type LoginInput = z.infer<typeof loginSchema>;
/** Parsed body of a profile update request. */
export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
/** Parsed body of a password change request. */
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
/** Parsed body of a vault item create/update request. */
export type VaultItemInput = z.infer<typeof vaultItemSchema>;
/** Parsed `:id` route parameter. */
export type IdParam = z.infer<typeof idParamSchema>;
