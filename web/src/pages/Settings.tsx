import { useMemo, useState, type FormEvent } from "react";
import { Field } from "../components/Field";
import { Button } from "../components/Button";
import { PasswordMeter } from "../components/PasswordMeter";
import { useAuth } from "../state/auth";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import { assessPassword } from "../lib/password";
import type { User } from "../lib/types";

export function Settings() {
  const { user, applyUser } = useAuth();
  const { notify } = useToast();

  const [name, setName] = useState(user?.name ?? "");
  const [savingName, setSavingName] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [savingPassword, setSavingPassword] = useState(false);
  const [passwordFailure, setPasswordFailure] = useState<{ message: string; code: string } | null>(
    null,
  );

  const assessment = useMemo(
    () => assessPassword(newPassword, { email: user?.email, name: user?.name }),
    [newPassword, user],
  );

  async function saveName(event: FormEvent) {
    event.preventDefault();
    setSavingName(true);
    setNameError(null);
    try {
      const { user: updated } = await api.patch<{ user: User }>("/me", { name });
      applyUser(updated);
      notify("Name updated.");
    } catch (error) {
      setNameError(error instanceof ApiError ? error.message : "The name could not be saved.");
    } finally {
      setSavingName(false);
    }
  }

  async function changePassword(event: FormEvent) {
    event.preventDefault();
    setSavingPassword(true);
    setPasswordFailure(null);
    try {
      await api.post("/me/password", { currentPassword, newPassword });
      setCurrentPassword("");
      setNewPassword("");
      notify("Password changed. Other devices have been signed out.");
    } catch (error) {
      setPasswordFailure(
        error instanceof ApiError
          ? { message: error.message, code: error.code }
          : { message: "The password could not be changed.", code: "NETWORK" },
      );
    } finally {
      setSavingPassword(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div className="shell">
          <p className="eyebrow">Settings</p>
          <h1 style={{ fontSize: "var(--fs-2xl)", marginTop: "var(--space-3)" }}>
            Manage this account.
          </h1>
        </div>
      </div>

      <div className="shell dash">
        <section className="panel">
          <div className="panel__head">
            <h2 className="panel__title">Display name</h2>
          </div>
          <form className="stack-4" onSubmit={saveName} noValidate>
            <Field
              label="Name"
              name="name"
              required
              minLength={2}
              maxLength={80}
              value={name}
              error={nameError}
              onChange={(e) => setName(e.target.value)}
            />
            <Button
              type="submit"
              busy={savingName}
              disabled={name.trim().length < 2 || name === user?.name}
            >
              {savingName ? "Saving" : "Save name"}
            </Button>
          </form>
        </section>

        <section className="panel">
          <div className="panel__head">
            <h2 className="panel__title">Password</h2>
            <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
              signs out other devices
            </span>
          </div>

          <form className="stack-4" onSubmit={changePassword} noValidate>
            {passwordFailure ? (
              <div className="alert" role="alert">
                <div>
                  {passwordFailure.message}
                  <span className="alert__code">{passwordFailure.code}</span>
                </div>
              </div>
            ) : null}

            <Field
              label="Current password"
              name="currentPassword"
              autoComplete="current-password"
              revealable
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />

            <Field
              label="New password"
              name="newPassword"
              autoComplete="new-password"
              revealable
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              hint="Changing this revokes every other session immediately."
            >
              <PasswordMeter value={newPassword} assessment={assessment} />
            </Field>

            <Button
              type="submit"
              variant="primary"
              busy={savingPassword}
              disabled={!assessment.ok || !currentPassword}
            >
              {savingPassword ? "Changing" : "Change password"}
            </Button>
          </form>
        </section>

        <section className="panel dash__full">
          <div className="panel__head">
            <h2 className="panel__title">Account</h2>
          </div>
          <div className="spec" style={{ border: 0 }}>
            <div className="spec__key">Identifier</div>
            <div className="spec__val mono" style={{ fontSize: "var(--fs-xs)" }}>
              {user?.id}
            </div>
            <div className="spec__key">Email</div>
            <div className="spec__val">{user?.email}</div>
            <div className="spec__key">Class</div>
            <div className="spec__val">{user?.role}</div>
            <div className="spec__key">Created</div>
            <div className="spec__val">
              {user ? new Date(user.createdAt).toLocaleString() : "—"}
            </div>
            <div className="spec__key">Password set</div>
            <div className="spec__val">
              {user ? new Date(user.passwordChangedAt).toLocaleString() : "—"}
            </div>
          </div>
        </section>
      </div>
    </>
  );
}
