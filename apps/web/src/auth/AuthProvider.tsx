// Browser authentication provider (ADR-018 / OIDC-B).
//
// A thin React adapter over the framework-agnostic AuthController: it constructs the controller with
// the real browser side effects (oidc-client-ts UserManager, /api/v1/me, sessionStorage seam), runs
// init once, and exposes the minimal context. All orchestration + security logic lives in the
// controller (node-testable); nothing here decodes tokens or uses localStorage.

import { createContext, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { UserManager } from "oidc-client-ts";

import { api } from "../api/client";
import {
  clearAccessTokenProvider,
  setAccessTokenProvider,
  setUnauthorizedHandler,
} from "./apiAuth";
import { AuthController } from "./authController";
import type { AuthControllerDeps, AuthSnapshot } from "./authController";
import { loadAuthConfig } from "./config";
import type { OidcClient } from "./oidc";
import { buildUserManagerSettings } from "./oidcSettings";
import {
  clearAuthSession,
  isDevFallbackActive,
  sessionStore,
  setDevFallbackActive,
} from "./session";
import type { AuthContextValue } from "./types";

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

// The real browser side effects wired into the controller.
function browserDeps(): AuthControllerDeps {
  return {
    loadConfig: loadAuthConfig,
    createOidcClient: (config): OidcClient => {
      const store = sessionStore();
      if (!store) throw new Error("session storage unavailable");
      return new UserManager(buildUserManagerSettings(config, window.location.origin, store));
    },
    fetchMe: () => api.me(),
    session: {
      isDevFallbackActive,
      setDevFallbackActive,
      clear: clearAuthSession,
    },
    tokenSeam: {
      setAccessTokenProvider,
      clearAccessTokenProvider,
      setUnauthorizedHandler,
    },
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const controllerRef = useRef<AuthController | null>(null);
  if (controllerRef.current === null) {
    controllerRef.current = new AuthController(browserDeps());
  }
  const controller = controllerRef.current;
  const [snapshot, setSnapshot] = useState<AuthSnapshot>(controller.getSnapshot());

  useEffect(() => {
    const unsubscribe = controller.subscribe(() => setSnapshot(controller.getSnapshot()));
    void controller.init();
    return () => {
      unsubscribe();
      controller.dispose();
    };
  }, [controller]);

  const value = useMemo<AuthContextValue>(
    () => ({
      status: snapshot.status,
      mode: snapshot.mode,
      principal: snapshot.principal,
      error: snapshot.error,
      login: (returnTo?: string) => controller.login(returnTo),
      continueAsDevFallback: () => controller.continueAsDevFallback(),
      completeCallback: () => controller.completeCallback(),
      logout: async () => {
        await controller.logout();
      },
    }),
    [snapshot, controller],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
