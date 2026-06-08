import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import * as api from "./api";
import { tokenStore, type AuthUser } from "./api";

interface AuthState {
  user: AuthUser | null;
  ready: boolean;
  signup: (email: string, password: string, orgName?: string) => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthCtx = createContext<AuthState>(null as unknown as AuthState);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!tokenStore.get()) {
      setReady(true);
      return;
    }
    api
      .getMe()
      .then(setUser)
      .catch(() => tokenStore.clear())
      .finally(() => setReady(true));
  }, []);

  const signup = async (email: string, password: string, orgName?: string) => {
    const { token, user } = await api.signup(email, password, orgName);
    tokenStore.set(token);
    setUser(user);
  };
  const login = async (email: string, password: string) => {
    const { token, user } = await api.login(email, password);
    tokenStore.set(token);
    setUser(user);
  };
  const logout = async () => {
    await api.logout().catch(() => undefined);
    tokenStore.clear();
    setUser(null);
  };

  return <AuthCtx.Provider value={{ user, ready, signup, login, logout }}>{children}</AuthCtx.Provider>;
}

export const useAuth = () => useContext(AuthCtx);
