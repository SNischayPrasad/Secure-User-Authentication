/** Shapes the API returns. These mirror the server's public contract exactly. */

export type User = {
  id: string;
  email: string;
  name: string;
  role: "user" | "admin";
  createdAt: number;
  passwordChangedAt: number;
};

export type Session = {
  id: string;
  current: boolean;
  userAgent: string | null;
  ipAddress: string | null;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
};

export type ActivityEvent = {
  id: string;
  type: string;
  outcome: "success" | "failure";
  detail: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: number;
};

export type VaultItem = {
  id: string;
  title: string;
  body: string;
  createdAt: number;
  updatedAt: number;
};

export type AuthPayload = {
  user: User;
  accessToken: string;
  expiresIn: number;
};
