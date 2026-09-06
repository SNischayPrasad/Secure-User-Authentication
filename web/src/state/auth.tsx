import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api, refreshOnce, setAccessToken, setAuthLostHandler } from "../lib/api";
import * as wire from "../lib/wire";
import type { AuthPayload, User } from "../lib/types";

type Status = "loading" | "authed" | "anon";

type AuthValue = {
  status: Status;
  user: User | null;
  /** When the current access token expires, as epoch milliseconds. */
  tokenExpiresAt: number | null;
  sessionStartedAt: number | null;
  register: (input: { name: string; email: string; password: string }) => Promise<void>;
  login: (input: { email: string; password: string }) => Promise<void>;
  logout: () => Promise<void>;
  logoutEverywhere: () => Promise<void>;
  refreshUser: () => Promise<void>;
  applyUser: (user: User) => void;
};

const AuthContext = createContext<AuthValue | null>(null);

/**
 * Holds the session for the whole app.
 *
 * On mount it asks for a CSRF token, then tries a silent refresh. That is what makes a
 * reload feel like a persistent login without ever putting a token somewhere script can
 * read it: the httpOnly cookie does the remembering, and the access token is minted fresh
 * into memory each time the tab loads.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [tokenExpiresAt, setTokenExpiresAt] = useState<number | null>(null);
  const [sessionStartedAt, setSessionStartedAt] = useState<number | null>(null);
  const bootstrapped = useRef(false);

  const adopt = useCallback((payload: AuthPayload) => {
    setAccessToken(payload.accessToken);
    setUser(payload.user);
    setTokenExpiresAt(Date.now() + payload.expiresIn * 1000);
    setSessionStartedAt((current) => current ?? Date.now());
    setStatus("authed");
  }, []);

  const forget = useCallback(() => {
    setAccessToken(null);
    setUser(null);
    setTokenExpiresAt(null);
    setSessionStartedAt(null);
    setStatus("anon");
    wire.clear();
  }, []);

  useEffect(() => {
    setAuthLostHandler(forget);
    return () => setAuthLostHandler(null);
  }, [forget]);

  useEffect(() => {
    if (bootstrapped.current) return;
    bootstrapped.current = true;

    void (async () => {
      try {
        await api.get<{ csrfToken: string }>("/auth/csrf");
      } catch {
        // A missing CSRF token only blocks mutations; reads still work, and the
        // sign-in form will request one again on submit.
      }

      const recovered = await refreshOnce();
      if (!recovered) {
        setStatus("anon");
        return;
      }

      try {
        const { user: me } = await api.get<{ user: User }>("/me");
        setUser(me);
        setSessionStartedAt(Date.now());
        setStatus("authed");
      } catch {
        forget();
      }
    })();
  }, [forget]);

  const register = useCallback(
    async (input: { name: string; email: string; password: string }) => {
      adopt(await api.post<AuthPayload>("/auth/register", input));
    },
    [adopt],
  );

  const login = useCallback(
    async (input: { email: string; password: string }) => {
      adopt(await api.post<AuthPayload>("/auth/login", input));
    },
    [adopt],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      forget();
    }
  }, [forget]);

  const logoutEverywhere = useCallback(async () => {
    try {
      await api.post("/auth/logout-all");
    } finally {
      forget();
    }
  }, [forget]);

  const refreshUser = useCallback(async () => {
    const { user: me } = await api.get<{ user: User }>("/me");
    setUser(me);
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      status,
      user,
      tokenExpiresAt,
      sessionStartedAt,
      register,
      login,
      logout,
      logoutEverywhere,
      refreshUser,
      applyUser: setUser,
    }),
    [status, user, tokenExpiresAt, sessionStartedAt, register, login, logout, logoutEverywhere, refreshUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside an AuthProvider.");
  return value;
}
