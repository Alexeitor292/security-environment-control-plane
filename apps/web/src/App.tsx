import { Outlet } from "react-router-dom";

import { api } from "./api/client";
import { AppShell } from "./components/shell/AppShell";
import { useAsync } from "./hooks";

export function App() {
  const me = useAsync(() => api.me(), []);
  const capabilities = useAsync(() => api.providerCapabilities(), []);

  return (
    <AppShell principal={me.data} capabilities={capabilities.data}>
      <Outlet />
    </AppShell>
  );
}
