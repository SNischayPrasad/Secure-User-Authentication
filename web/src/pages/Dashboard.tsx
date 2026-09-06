import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { CredentialCard } from "../components/CredentialCard";
import { WirePanel } from "../components/WirePanel";
import { Button } from "../components/Button";
import { Field } from "../components/Field";
import { useAuth } from "../state/auth";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { Session, VaultItem } from "../lib/types";

const WHEN = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
});

export function Dashboard() {
  const { user, tokenExpiresAt } = useAuth();
  const { notify } = useToast();

  const [items, setItems] = useState<VaultItem[] | null>(null);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const loadVault = useCallback(async () => {
    const { items: rows } = await api.get<{ items: VaultItem[] }>("/vault");
    setItems(rows);
  }, []);

  const bootstrapped = useRef(false);

  useEffect(() => {
    // React StrictMode invokes effects twice in development. Without this guard the bootstrap
    // fetches fire twice and the Wire panel below reports duplicate requests that the app is
    // not really making in production.
    if (bootstrapped.current) return;
    bootstrapped.current = true;

    void (async () => {
      try {
        await loadVault();
      } catch (error) {
        setFailure(error instanceof ApiError ? error.message : "The vault could not be loaded.");
        setItems([]);
      }

      try {
        const { sessions } = await api.get<{ sessions: Session[] }>("/me/sessions");
        setCurrentSessionId(sessions.find((s) => s.current)?.id ?? null);
      } catch {
        // The credential simply shows no session id if this fails; nothing else depends on it.
      }
    })();
  }, [loadVault]);

  async function addItem(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setFailure(null);
    try {
      await api.post("/vault", { title, body });
      setTitle("");
      setBody("");
      await loadVault();
      notify("Note added.");
    } catch (error) {
      setFailure(error instanceof ApiError ? error.message : "The note could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  async function removeItem(id: string) {
    try {
      await api.del(`/vault/${id}`);
      await loadVault();
      notify("Note deleted.");
    } catch (error) {
      notify(error instanceof ApiError ? error.message : "The note could not be deleted.", "err");
    }
  }

  return (
    <>
      <div className="page-head">
        <div className="shell spread">
          <div>
            <p className="eyebrow">Dashboard</p>
            <h1 style={{ fontSize: "var(--fs-2xl)", marginTop: "var(--space-3)" }}>
              {user ? `Signed in as ${user.name}` : "Dashboard"}
            </h1>
          </div>
          <span className="pill pill--verified">
            <span className="dot" />
            Authenticated
          </span>
        </div>
      </div>

      <div className="shell dash">
        <section className="stack-5">
          <CredentialCard user={user} sessionId={currentSessionId} expiresAt={tokenExpiresAt} />

          <div className="panel">
            <div className="panel__head">
              <h2 className="panel__title">Vault — protected data</h2>
              <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                GET /api/v1/vault · bearer only
              </span>
            </div>

            {failure ? (
              <div className="alert" role="alert" style={{ marginBottom: "var(--space-4)" }}>
                <div>{failure}</div>
              </div>
            ) : null}

            {items === null ? (
              <div className="stack-2">
                <div className="skeleton" />
                <div className="skeleton" style={{ width: "70%" }} />
              </div>
            ) : items.length === 0 ? (
              <div className="empty">
                <div className="empty__title">The vault is empty</div>
                <p>Add a note below. Only this account can read it back.</p>
              </div>
            ) : (
              <div>
                {items.map((item) => (
                  <article className="vault-item" key={item.id}>
                    <h3 className="vault-item__title">{item.title}</h3>
                    <p className="vault-item__body">{item.body}</p>
                    <div className="vault-item__foot">
                      <span>{WHEN.format(item.updatedAt)}</span>
                      <Button size="sm" variant="danger" onClick={() => void removeItem(item.id)}>
                        Delete
                      </Button>
                    </div>
                  </article>
                ))}
              </div>
            )}

            <form className="stack-4" onSubmit={addItem} style={{ marginTop: "var(--space-5)" }}>
              <Field
                label="New note"
                name="title"
                required
                maxLength={120}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Title"
              />
              <div className="field">
                <label className="field__label" htmlFor="vault-body">
                  <span>Contents</span>
                </label>
                <textarea
                  id="vault-body"
                  className="field__input"
                  required
                  maxLength={4000}
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder="Only readable while signed in as this account."
                />
              </div>
              <Button type="submit" busy={busy} disabled={!title.trim() || !body.trim()}>
                {busy ? "Saving" : "Add note"}
              </Button>
            </form>
          </div>
        </section>

        <section className="stack-5">
          <WirePanel />

          <div className="panel">
            <div className="panel__head">
              <h2 className="panel__title">This credential</h2>
            </div>
            <div className="spec" style={{ border: 0 }}>
              <div className="spec__key">Holder</div>
              <div className="spec__val">{user?.email}</div>
              <div className="spec__key">Class</div>
              <div className="spec__val">{user?.role}</div>
              <div className="spec__key">Session</div>
              <div className="spec__val mono" style={{ fontSize: "var(--fs-xs)" }}>
                {currentSessionId ?? "—"}
              </div>
              <div className="spec__key">Token</div>
              <div className="spec__val">
                {tokenExpiresAt
                  ? `expires ${new Date(tokenExpiresAt).toLocaleTimeString()}, then refreshes silently`
                  : "—"}
              </div>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}
