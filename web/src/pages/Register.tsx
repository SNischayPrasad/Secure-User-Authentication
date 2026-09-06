import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Field } from "../components/Field";
import { Button } from "../components/Button";
import { PasswordMeter } from "../components/PasswordMeter";
import { CredentialCard } from "../components/CredentialCard";
import { useAuth } from "../state/auth";
import { useToast } from "../components/Toast";
import { ApiError, fieldIssues } from "../lib/api";
import { assessPassword } from "../lib/password";

export function Register() {
  const { register } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ message: string; code: string } | null>(null);
  const [issues, setIssues] = useState<Record<string, string>>({});

  const assessment = useMemo(
    () => assessPassword(password, { email, name }),
    [password, email, name],
  );

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setFailure(null);
    setIssues({});

    try {
      await register({ name, email, password });
      notify("Account created.");
      navigate("/dashboard", { replace: true });
    } catch (error) {
      if (error instanceof ApiError) {
        const perField = Object.fromEntries(fieldIssues(error).map((i) => [i.field, i.message]));
        setIssues(perField);
        if (!Object.keys(perField).length) {
          setFailure({ message: error.message, code: error.code });
        }
      } else {
        setFailure({ message: "The server could not be reached.", code: "NETWORK" });
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <div className="auth__form-side">
        <div className="auth__card">
          <p className="eyebrow">New holder</p>
          <h1 className="auth__title" style={{ marginTop: "var(--space-4)" }}>
            Get issued a credential.
          </h1>

          <form
            className="stack-5"
            onSubmit={handleSubmit}
            noValidate
            style={{ marginTop: "var(--space-6)" }}
          >
            {failure ? (
              <div className="alert" role="alert">
                <div>
                  {failure.message}
                  <span className="alert__code">{failure.code}</span>
                </div>
              </div>
            ) : null}

            <Field
              label="Name"
              name="name"
              autoComplete="name"
              required
              minLength={2}
              value={name}
              error={issues.name ?? null}
              onChange={(e) => setName(e.target.value)}
              placeholder="Ada Lovelace"
            />

            <Field
              label="Email"
              type="email"
              name="email"
              autoComplete="email"
              inputMode="email"
              required
              value={email}
              error={issues.email ?? null}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="ada@example.com"
            />

            <Field
              label="Password"
              name="password"
              autoComplete="new-password"
              revealable
              required
              value={password}
              error={issues.password ?? null}
              onChange={(e) => setPassword(e.target.value)}
              hint="At least 12 characters, mixing three of: lower case, upper case, digits, symbols."
            >
              <PasswordMeter value={password} assessment={assessment} />
            </Field>

            <Button
              type="submit"
              variant="primary"
              block
              busy={busy}
              disabled={!assessment.ok || !name || !email}
            >
              {busy ? "Creating" : "Create account"}
            </Button>
          </form>

          <p className="auth__switch">
            Already have an account? <Link to="/login">Sign in</Link>.
          </p>
        </div>
      </div>

      <aside className="auth__aside">
        <CredentialCard
          user={
            name || email
              ? {
                  id: "usr_preview",
                  email: email || "not yet supplied",
                  name: name || "Unnamed holder",
                  role: "user",
                  createdAt: Date.now(),
                  passwordChangedAt: Date.now(),
                }
              : null
          }
          sessionId="ses_preview"
          expiresAt={Date.now() + 900_000}
        />
        <p className="muted" style={{ maxWidth: "34ch" }}>
          A preview, updating as you type. The machine-readable zone is generated with real ICAO
          check digits, so it stays consistent with the fields above it.
        </p>
      </aside>
    </div>
  );
}
