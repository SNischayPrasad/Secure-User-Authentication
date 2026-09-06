import { useEffect, useState } from "react";
import * as wire from "../lib/wire";

function statusClass(status: number): string {
  if (status >= 500) return "code-5xx";
  if (status >= 400) return "code-4xx";
  if (status >= 300) return "code-3xx";
  return "code-2xx";
}

/**
 * A live log of the HTTP exchanges this page has actually made.
 *
 * The brief asks for an example authenticated request. Rather than pasting one into a README and
 * hoping it still matches, this shows the real ones as they happen — including which carried a
 * bearer token and what the server answered. Token values are never recorded, only their presence.
 */
export function WirePanel() {
  const [entries, setEntries] = useState(wire.snapshot);

  useEffect(() => wire.subscribe(setEntries), []);

  return (
    <section className="panel">
      <div className="panel__head">
        <h2 className="panel__title">Wire</h2>
        <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
          live requests from this tab
        </span>
      </div>

      {entries.length === 0 ? (
        <div className="empty">
          <div className="empty__title">Nothing on the wire yet</div>
          <p>Requests appear here the moment this page makes one.</p>
        </div>
      ) : (
        <div className="wire">
          {entries.map((entry) => (
            <div className="wire__row" key={entry.id}>
              <span className={statusClass(entry.status)}>
                {entry.status}
                {entry.authenticated ? <span className="ledger__lock" title="sent with a bearer token"> ●</span> : null}
              </span>
              <span className="wire__path" title={`${entry.method} ${entry.path}`}>
                <span className={`m-${entry.method}`}>{entry.method}</span> {entry.path}
                {entry.code ? <span className="muted"> · {entry.code}</span> : null}
              </span>
              <span className="wire__ms">{entry.ms} ms</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
