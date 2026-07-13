import { Outlet } from "react-router-dom";

import { api } from "./api/client";
import { useAuth } from "./auth/AuthProvider";
import { AppShell } from "./components/shell/AppShell";
import { useAsync } from "./hooks";

export function App() {
  // The authoritative identity comes from the auth layer (/api/v1/me), not a duplicate fetch or any
  // token claim. App renders only inside the authenticated boundary, so this is always resolved.
  const { principal, logout } = useAuth();
  const capabilities = useAsync(() => api.providerCapabilities(), []);

  return (
    <AppShell principal={principal} capabilities={capabilities.data} onLogout={() => void logout()}>
      <Outlet />
    </AppShell>
  );
}
