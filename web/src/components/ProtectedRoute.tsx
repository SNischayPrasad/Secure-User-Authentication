import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../state/auth";

/**
 * Gate for authenticated views.
 *
 * While the silent refresh is still in flight the status is "loading", and rendering a redirect
 * then would bounce a legitimately signed-in person to the sign-in page on every reload. So the
 * loading state gets a placeholder, and only a settled "anon" redirects.
 */
export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === "loading") {
    return (
      <div className="shell centre-note">
        <div className="eyebrow">Verifying credential</div>
        <div className="skeleton" style={{ width: "min(28rem, 80vw)", height: "0.9rem" }} />
      </div>
    );
  }

  if (status === "anon") {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return <>{children}</>;
}
