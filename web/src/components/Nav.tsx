import { Link, NavLink, useNavigate } from "react-router-dom";
import { Seal } from "./Seal";
import { Button } from "./Button";
import { useAuth } from "../state/auth";

/** The one persistent chrome. It shows who is signed in, because a credential system should. */
export function Nav() {
  const { status, user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <header className="nav">
      <div className="nav__inner">
        <Link to="/" className="nav__brand">
          <Seal className="seal" title="Credential" />
          <span>Credential</span>
        </Link>

        <nav className="nav__links" aria-label="Main">
          {status === "authed" ? (
            <>
              <span className="nav__who" title={user?.email}>
                {user?.email}
              </span>
              <NavLink to="/dashboard" className="nav__link">
                Dashboard
              </NavLink>
              <NavLink to="/sessions" className="nav__link">
                Sessions
              </NavLink>
              <NavLink to="/settings" className="nav__link">
                Settings
              </NavLink>
              <Button
                size="sm"
                variant="ghost"
                onClick={async () => {
                  await logout();
                  navigate("/");
                }}
              >
                Sign out
              </Button>
            </>
          ) : (
            <>
              <a className="nav__link" href="/#surface">
                API
              </a>
              <NavLink to="/login" className="nav__link">
                Sign in
              </NavLink>
              <Link to="/register">
                <Button size="sm" variant="primary">
                  Create account
                </Button>
              </Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}
