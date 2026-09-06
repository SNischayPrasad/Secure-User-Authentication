import { Router, type Request } from "express";

import { AppError } from "../lib/errors.js";
import { authenticate } from "../middleware/authenticate.js";
import { requireCsrf } from "../middleware/csrf.js";
import { validate } from "../middleware/validate.js";
import { idParamSchema, vaultItemSchema } from "../schemas/auth.js";
import {
  create as createItem,
  listForUser as listItems,
  toPublicVaultItem,
  remove as deleteItem,
  update as updateItem,
} from "../services/vaultService.js";

/** Partial form of the vault payload for PATCH, so a caller can change one field at a time. */
const vaultItemPatchSchema = vaultItemSchema.partial();

/** The auth context the `authenticate` middleware attaches to the request. */
type AuthContext = NonNullable<Request["auth"]>;

/** Returns the authenticated context, or 401 if the route was mounted without `authenticate`. */
function requireAuthContext(req: { auth?: AuthContext }): AuthContext {
  if (!req.auth) {
    throw new AppError(401, "AUTH_REQUIRED", "Sign in to continue.");
  }
  return req.auth;
}

/** Reads a validated path parameter; `noUncheckedIndexedAccess` makes the lookup optional. */
function pathParam(req: { params?: unknown }, key: string): string {
  const params = req.params as Record<string, unknown> | undefined | null;
  const value = params ? params[key] : undefined;
  return typeof value === "string" ? value : "";
}

/**
 * Vault routes — the protected resource the UI showcases. Mounted at `/api/v1/vault`; every
 * route sits behind `authenticate` and every query is scoped to the caller's user id, so one
 * account can never read or edit another account's items.
 */
const router = Router();

router.use(authenticate);

/** Endpoint 14 — GET /vault. Lists only the caller's items, newest change first. */
router.get("/", (req, res) => {
  const auth = requireAuthContext(req);
  res.status(200).json({ items: listItems(auth.user.id).map(toPublicVaultItem) });
});

/** Endpoint 15 — POST /vault. Creates an item owned by the caller. */
router.post("/", requireCsrf, validate({ body: vaultItemSchema }), (req, res) => {
  const auth = requireAuthContext(req);
  const body = req.body as { title: string; body: string };

  const item = createItem(auth.user.id, { title: body.title, body: body.body });

  res.status(201).json({ item: toPublicVaultItem(item) });
});

/**
 * Endpoint 16 — PATCH /vault/:id. Ownership is part of the update predicate, and a miss returns
 * 404 rather than 403 so the endpoint does not confirm that another user's item exists.
 */
router.patch(
  "/:id",
  requireCsrf,
  validate({ params: idParamSchema, body: vaultItemPatchSchema }),
  (req, res) => {
    const auth = requireAuthContext(req);
    const id = pathParam(req, "id");
    const patch = req.body as { title?: string; body?: string };

    if (patch.title === undefined && patch.body === undefined) {
      throw new AppError(400, "VALIDATION_FAILED", "Provide a title or a body to update.", [
        { field: "title", message: "Provide a title or a body to update." },
      ]);
    }

    const item = updateItem(auth.user.id, id, patch);
    if (!item) {
      throw new AppError(404, "NOT_FOUND", "That item does not exist.");
    }

    res.status(200).json({ item: toPublicVaultItem(item) });
  },
);

/** Endpoint 17 — DELETE /vault/:id. Scoped to the caller; 404 when the item is not theirs. */
router.delete("/:id", requireCsrf, validate({ params: idParamSchema }), (req, res) => {
  const auth = requireAuthContext(req);
  const id = pathParam(req, "id");

  const removed = deleteItem(auth.user.id, id);
  if (!removed) {
    throw new AppError(404, "NOT_FOUND", "That item does not exist.");
  }

  res.status(204).end();
});

/** Router for `/api/v1/vault` (endpoints 14-17). */
export default router;
