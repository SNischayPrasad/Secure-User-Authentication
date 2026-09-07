import { Link } from "react-router-dom";
import { CredentialCard } from "../components/CredentialCard";
import { Button } from "../components/Button";
import { ENDPOINTS } from "../lib/endpoints";
import { useAuth } from "../state/auth";

const SPECIFICATION: Array<{ key: string; value: React.ReactNode }> = [
  {
    key: "Hashing",
    value: (
      <>
        <strong>Argon2id</strong>, m=19456 KiB · t=2 · p=1 · 32-byte output. The OWASP minimum, with
        a per-password salt. Plaintext is never written anywhere, including logs.
      </>
    ),
  },
  {
    key: "Access token",
    value: (
      <>
        <strong>JWT HS256</strong>, fifteen minutes. Issuer, audience and algorithm are all verified
        on every request — an unsigned <span className="mono">alg: none</span> token is rejected.
      </>
    ),
  },
  {
    key: "Refresh token",
    value: (
      <>
        <strong>Opaque 256-bit</strong>, stored only as a SHA-256 digest, delivered in an httpOnly
        SameSite=Strict cookie. Script cannot read it, so an XSS payload cannot steal it.
      </>
    ),
  },
  {
    key: "Rotation",
    value: (
      <>
        Every refresh mints a new token and retires the old one. Presenting a retired token is
        treated as theft: <strong>the entire token family is revoked</strong> and the session ends.
      </>
    ),
  },
  {
    key: "Revocation",
    value: (
      <>
        Sessions are checked on every authenticated request, so signing out everywhere cuts off
        access tokens that have not expired yet. Changing a password does the same to other devices.
      </>
    ),
  },
  {
    key: "Lockout",
    value: (
      <>
        Five wrong passwords locks the account for fifteen minutes and answers{" "}
        <span className="mono code-4xx">423</span>. Unknown emails still run a dummy verification,
        so response timing cannot be used to discover who has an account.
      </>
    ),
  },
];

export function Landing() {
  const { status, user, tokenExpiresAt } = useAuth();

  return (
    <>
      <section className="hero shell">
        <div className="hero__grid">
          <div>
            <p className="eyebrow">Reference implementation</p>

            <h1 className="hero__title">
              A credential you can <em>take back</em>.
            </h1>

            <p className="lede stack-4" style={{ marginTop: "var(--space-5)" }}>
              Register, sign in, and watch the machinery work: Argon2id hashing, a fifteen-minute
              access token, and a refresh token that rotates on every use. Replay an old one and the
              whole family is revoked.
            </p>

            <div className="hero__actions">
              {status === "authed" ? (
                <Link to="/dashboard">
                  <Button variant="primary">Open dashboard</Button>
                </Link>
              ) : (
                <>
                  <Link to="/register">
                    <Button variant="primary">Create account</Button>
                  </Link>
                  <Link to="/login">
                    <Button>Sign in</Button>
                  </Link>
                </>
              )}
            </div>

            <p className="hero__note">
              Demo account:{" "}
              <span style={{ color: "var(--paper-dim)" }}>ada@example.com</span> ·{" "}
              <span style={{ color: "var(--paper-dim)" }}>correct-horse-battery-staple-9</span>
            </p>
          </div>

          <CredentialCard
            user={user}
            sessionId={null}
            expiresAt={tokenExpiresAt}
          />
        </div>
      </section>

      <section className="band shell">
        <p className="eyebrow">What the server enforces</p>
        <div className="spec stack-6" style={{ marginTop: "var(--space-5)" }}>
          {SPECIFICATION.map((row) => (
            <div key={row.key} style={{ display: "contents" }}>
              <div className="spec__key">{row.key}</div>
              <div className="spec__val">{row.value}</div>
            </div>
          ))}
        </div>
        <p className="hero__note">
          Every line above is asserted by <span className="mono">scripts/smoke.mjs</span> against a
          running server, and by the test suite.
        </p>
      </section>

      <section className="band shell" id="surface">
        <div className="spread">
          <p className="eyebrow" style={{ flex: 1 }}>
            The surface
          </p>
        </div>

        <div className="ledger-wrap" style={{ marginTop: "var(--space-5)" }}>
          <table className="ledger">
            <caption className="sr-only">Every endpoint the API exposes</caption>
            <thead>
              <tr>
                <th scope="col">Method</th>
                <th scope="col">Path</th>
                <th scope="col">Auth</th>
                <th scope="col">Purpose</th>
                <th scope="col">OK</th>
              </tr>
            </thead>
            <tbody>
              {ENDPOINTS.map((endpoint) => (
                <tr key={`${endpoint.method} ${endpoint.path}`}>
                  <td className={`ledger__method m-${endpoint.method}`}>{endpoint.method}</td>
                  <td className="ledger__path">{endpoint.path}</td>
                  <td>
                    {endpoint.auth === "public" ? (
                      <span className="muted">—</span>
                    ) : endpoint.auth === "bearer" ? (
                      <span className="ledger__lock">bearer</span>
                    ) : (
                      <span className="ledger__lock">cookie</span>
                    )}
                  </td>
                  <td>{endpoint.purpose}</td>
                  <td className="code-2xx">{endpoint.success}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="band shell">
        <p className="eyebrow">An authenticated request</p>

        <div className="dash" style={{ paddingBlock: "var(--space-5)" }}>
          <div className="stack-4">
            <p className="muted">
              Sign in, keep the access token, and send it as a bearer credential. The protected
              route answers with data only when that token is valid and its session is still live.
            </p>
            <pre className="snippet">
              <code>
                {`# 1 — sign in and keep the access token
`}
                <b>TOKEN</b>
                {`=$(curl -s -X POST http://localhost:4000/api/v1/auth/login \\
  -H '`}
                <u>Content-Type: application/json</u>
                {`' \\
  -d '{"email":"ada@example.com","password":"correct-horse-battery-staple-9"}' \\
  | node -pe 'JSON.parse(require("fs").readFileSync(0)).accessToken')

# 2 — call the protected route with it
curl -s http://localhost:4000/api/v1/me \\
  -H "`}
                <b>Authorization: Bearer $TOKEN</b>
                {`"`}
              </code>
            </pre>
          </div>

          <div className="stack-4">
            <p className="muted">The response, and what happens without the header.</p>
            <pre className="snippet">
              <code>
                <i>{`200 OK`}</i>
                {`
{
  "user": {
    "id": "usr_TF2RVVY69QGMRPTTDX0KY",
    "email": "ada@example.com",
    "name": "Ada Lovelace",
    "role": "user",
    "createdAt": 1757150400000,
    "passwordChangedAt": 1757150400000
  }
}

`}
                <u># same request, no Authorization header</u>
                {`
`}
                <span className="code-4xx">401 Unauthorized</span>
                {`
{
  "error": {
    "code": "AUTH_REQUIRED",
    "message": "Sign in to continue."
  },
  "requestId": "req_GNE9FBNBAH9WDTN0S0CV0"
}`}
              </code>
            </pre>
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="shell spread">
          <span>
            Secure User Authentication — a working reference implementation, not a product.
          </span>
          <span className="footer__mono">Argon2id · JWT HS256 · rotating refresh · PostgreSQL</span>
        </div>
      </footer>
    </>
  );
}
