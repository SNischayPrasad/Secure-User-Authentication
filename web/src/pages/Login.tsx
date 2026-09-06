import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Field } from "../components/Field";
import { Button } from "../components/Button";
import { CredentialCard } from "../components/CredentialCard";
import { useAuth } from "../state/auth";
import { useToast } from "../components/Toast";
import { ApiError, fieldIssues } from "../lib/api";

export function Login() {
  const { login } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ message: string; code: string } | null>(null);
  const [issues, setIssues] = useState<Record<string, string>>({});

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setFailure(null);
    setIssues({});

    try {
      await login({ email, password });
      notify("Signed in.");
      navigate(from, { replace: true });
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
          <p className="eyebrow">Sign in</p>
          <h1 className="auth__title" style={{ marginTop: "var(--space-4)" }}>
            Present your credential.
          </h1>

          <form className="stack-5" onSubmit={handleSubmit} noValidate style={{ marginTop: "var(--space-6)" }}>
            {failure ? (
              <div className="alert" role="alert">
                <div>
                  {failure.message}
                  <span className="alert__code">{failure.code}</span>
                </div>
              </div>
            ) : null}

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
              autoComplete="current-password"
              revealable
              required
              value={password}
              error={issues.password ?? null}
              onChange={(e) => setPassword(e.target.value)}
            />

            <Button type="submit" variant="primary" block busy={busy}>
              {busy ? "Checking" : "Sign in"}
            </Button>
          </form>

          <p className="auth__switch">
            No account yet? <Link to="/register">Create one</Link>.
          </p>
        </div>
      </div>

      <aside className="auth__aside">
        <CredentialCard user={null} />
        <p className="muted" style={{ maxWidth: "34ch" }}>
          Until you sign in, the credential is a specimen: the machine-readable zone reads
          <span className="mono"> NOT ISSUED</span> because there is genuinely nothing to encode.
        </p>
      </aside>
    </div>
  );
}
