import { useCallback, useRef, useState } from "react";
import { Guilloche } from "./Guilloche";
import { Seal } from "./Seal";
import { Mrz } from "./Mrz";
import { anonymousMrz, credentialMrz } from "../lib/mrz";
import type { User } from "../lib/types";

const DATE = new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", year: "numeric" });

type Props = {
  user: User | null;
  sessionId?: string | null;
  expiresAt?: number | null;
};

/**
 * The credential itself: guilloche linework, a foil seal, the holder's details, and a real
 * machine-readable zone along the bottom edge.
 *
 * The MRZ is the point. It is not decoration — it encodes the signed-in user's id, role, issue
 * and expiry dates and session id with genuine ICAO check digits, so signing out or revoking a
 * session visibly changes the strip. The document and the database always agree.
 */
export function CredentialCard({ user, sessionId, expiresAt }: Props) {
  const frame = useRef<HTMLDivElement>(null);
  const [tilt, setTilt] = useState<{ x: number; y: number } | null>(null);

  const handleMove = useCallback((event: React.PointerEvent<HTMLDivElement>) => {
    if (event.pointerType !== "mouse") return;
    const box = frame.current?.getBoundingClientRect();
    if (!box) return;
    const px = (event.clientX - box.left) / box.width - 0.5;
    const py = (event.clientY - box.top) / box.height - 0.5;
    setTilt({ x: -py * 6, y: px * 6 });
  }, []);

  const issuedAt = user?.createdAt ?? Date.now();
  const validUntil = expiresAt ?? issuedAt;

  const lines = user
    ? credentialMrz({
        name: user.name,
        email: user.email,
        userId: user.id,
        role: user.role,
        sessionId: sessionId ?? "ses_none",
        issuedAt,
        expiresAt: validUntil,
      })
    : anonymousMrz();

  return (
    <div
      className="cred-frame"
      ref={frame}
      onPointerMove={handleMove}
      onPointerLeave={() => setTilt(null)}
    >
      <article
        className="cred"
        style={
          tilt ? { transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)` } : undefined
        }
      >
        <Guilloche className="cred__guilloche" />
        <span className="cred__sheen" />

        <div className="cred__body">
          <header className="cred__top">
            <div>
              <div className="cred__issuer">Credential</div>
              <div className="cred__kind">
                {user ? "Holder credential" : "Specimen · not issued"}
              </div>
            </div>
            <Seal className="cred__seal" />
          </header>

          <div className="cred__fields">
            <div>
              <div className="cred__field-label">Holder</div>
              <div className="cred__field-value">{user ? user.name : "No holder"}</div>
            </div>
            <div>
              <div className="cred__field-label">Identifier</div>
              <div className="cred__field-value cred__field-value--sm">
                {user ? user.email : "sign in to be issued a credential"}
              </div>
            </div>
            <div className="cred__meta">
              <div>
                <div className="cred__field-label">Issued</div>
                <div className="cred__field-value cred__field-value--sm">
                  {user ? DATE.format(issuedAt) : "—"}
                </div>
              </div>
              <div>
                <div className="cred__field-label">Class</div>
                <div className="cred__field-value cred__field-value--sm">
                  {user ? user.role.toUpperCase() : "—"}
                </div>
              </div>
              <div>
                <div className="cred__field-label">Token expires</div>
                <div className="cred__field-value cred__field-value--sm">
                  {user && expiresAt
                    ? new Date(expiresAt).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })
                    : "—"}
                </div>
              </div>
            </div>
          </div>
        </div>

        <Mrz lines={lines} className="cred__mrz" />
      </article>
    </div>
  );
}
