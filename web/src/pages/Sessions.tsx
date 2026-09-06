import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../components/Button";
import { useAuth } from "../state/auth";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { ActivityEvent, Session } from "../lib/types";

const WHEN = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
});

/** Turns a raw user-agent into something a person can recognise their own device by. */
function device(userAgent: string | null): string {
  if (!userAgent) return "Unknown device";
  const browser =
    /Edg\//.test(userAgent) ? "Edge"
    : /Chrome\//.test(userAgent) ? "Chrome"
    : /Firefox\//.test(userAgent) ? "Firefox"
    : /Safari\//.test(userAgent) ? "Safari"
    : "Unknown browser";
  const platform =
    /Windows/.test(userAgent) ? "Windows"
    : /Android/.test(userAgent) ? "Android"
    : /iPhone|iPad/.test(userAgent) ? "iOS"
    : /Mac OS X/.test(userAgent) ? "macOS"
    : /Linux/.test(userAgent) ? "Linux"
    : "";
  return platform ? `${browser} on ${platform}` : browser;
}

export function Sessions() {
  const { logoutEverywhere } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();

  const [sessions, setSessions] = useState<Session[] | null>(null);
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);

  const load = useCallback(async () => {
    const [{ sessions: rows }, { events: log }] = await Promise.all([
      api.get<{ sessions: Session[] }>("/me/sessions"),
      api.get<{ events: ActivityEvent[] }>("/me/activity"),
    ]);
    setSessions(rows);
    setEvents(log);
  }, []);

  const bootstrapped = useRef(false);

  useEffect(() => {
    // See the note in Dashboard: StrictMode double-invokes effects in development.
    if (bootstrapped.current) return;
    bootstrapped.current = true;

    void load().catch(() => {
      setSessions([]);
      setEvents([]);
    });
  }, [load]);

  async function revoke(id: string) {
    try {
      await api.del(`/me/sessions/${id}`);
      await load();
      notify("Session revoked.");
    } catch (error) {
      notify(error instanceof ApiError ? error.message : "The session could not be revoked.", "err");
    }
  }

  return (
    <>
      <div className="page-head">
        <div className="shell spread">
          <div>
            <p className="eyebrow">Sessions</p>
            <h1 style={{ fontSize: "var(--fs-2xl)", marginTop: "var(--space-3)" }}>
              Where this account is signed in.
            </h1>
          </div>
          <Button
            variant="danger"
            onClick={async () => {
              await logoutEverywhere();
              notify("Signed out everywhere.");
              navigate("/login");
            }}
          >
            Sign out everywhere
          </Button>
        </div>
      </div>

      <div className="shell" style={{ paddingBlock: "var(--space-6)" }}>
        <section className="panel">
          <div className="panel__head">
            <h2 className="panel__title">Active sessions</h2>
            <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
              revoking one takes effect on the next request, not when its token expires
            </span>
          </div>

          {sessions === null ? (
            <div className="stack-2">
              <div className="skeleton" />
              <div className="skeleton" style={{ width: "60%" }} />
            </div>
          ) : sessions.length === 0 ? (
            <div className="empty">
              <div className="empty__title">No active sessions</div>
            </div>
          ) : (
            <div className="ledger-wrap">
              <table className="ledger">
                <thead>
                  <tr>
                    <th scope="col">Device</th>
                    <th scope="col">Address</th>
                    <th scope="col">Started</th>
                    <th scope="col">Last used</th>
                    <th scope="col" />
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.id}>
                      <td className="ledger__path">
                        {device(session.userAgent)}{" "}
                        {session.current ? (
                          <span className="pill pill--verified" style={{ marginLeft: 6 }}>
                            this device
                          </span>
                        ) : null}
                      </td>
                      <td>{session.ipAddress ?? "—"}</td>
                      <td>{WHEN.format(session.createdAt)}</td>
                      <td>{WHEN.format(session.lastUsedAt)}</td>
                      <td>
                        {session.current ? (
                          <span className="muted">—</span>
                        ) : (
                          <Button size="sm" variant="danger" onClick={() => void revoke(session.id)}>
                            Revoke
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="panel" style={{ marginTop: "var(--space-5)" }}>
          <div className="panel__head">
            <h2 className="panel__title">Recent activity</h2>
            <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
              append-only audit log
            </span>
          </div>

          {events === null ? (
            <div className="skeleton" />
          ) : events.length === 0 ? (
            <div className="empty">
              <div className="empty__title">Nothing recorded yet</div>
            </div>
          ) : (
            <div className="ledger-wrap">
              <table className="ledger">
                <thead>
                  <tr>
                    <th scope="col">Event</th>
                    <th scope="col">Outcome</th>
                    <th scope="col">Detail</th>
                    <th scope="col">Address</th>
                    <th scope="col">When</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={event.id}>
                      <td className="ledger__path">{event.type}</td>
                      <td className={event.outcome === "success" ? "code-2xx" : "code-5xx"}>
                        {event.outcome}
                      </td>
                      <td>{event.detail ?? "—"}</td>
                      <td>{event.ipAddress ?? "—"}</td>
                      <td>{WHEN.format(event.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
