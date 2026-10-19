import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "./api";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Websites from "./pages/Websites";
import LiveActivity from "./pages/LiveActivity";
import Investigations from "./pages/Investigations";
import InvestigationDetail from "./pages/InvestigationDetail";
import Defenses from "./pages/Defenses";
import Integrations from "./pages/Integrations";
import AgentSettings from "./pages/AgentSettings";
import Reports from "./pages/Reports";

const NAV = [
  ["Overview", "/"], ["Protected Websites", "/websites"], ["Live Activity", "/activity"],
  ["Investigations", "/investigations"], ["Active Defenses", "/defenses"],
  ["Integrations", "/integrations"], ["Agent Settings", "/agent"], ["Security Reports", "/reports"],
];

export default function App() {
  const [user, setUser] = useState<any>(undefined);
  useEffect(() => { api("/api/auth/me").then(setUser).catch(() => setUser(null)); }, []);
  if (user === undefined) return <div className="p-8 text-gray-500">Loading...</div>;
  if (!user) return <Login onLogin={setUser} />;

  return (
    <div className="min-h-screen flex">
      <aside className="w-56 bg-ink-800 border-r border-ink-700 p-4 flex flex-col gap-1 shrink-0">
        <div className="mb-4">
          <div className="text-lg font-bold text-cyan-400">Sentinel AI</div>
          <div className="text-xs text-gray-500">Autonomous security agent</div>
        </div>
        {NAV.map(([label, to]) => (
          <NavLink key={to} to={to} end={to === "/"}
            className={({ isActive }) => `px-3 py-2 rounded text-sm ${isActive ? "bg-ink-700 text-cyan-300" : "text-gray-400 hover:text-gray-200"}`}>
            {label}
          </NavLink>
        ))}
        <button className="mt-auto text-left px-3 py-2 text-sm text-gray-500 hover:text-gray-300"
          onClick={async () => { await api("/api/auth/logout", { method: "POST" }); location.reload(); }}>
          Sign out ({user.email})
        </button>
      </aside>
      <main className="flex-1 p-6 overflow-auto">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/websites" element={<Websites />} />
          <Route path="/activity" element={<LiveActivity />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/investigations/:id" element={<InvestigationDetail />} />
          <Route path="/defenses" element={<Defenses />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/agent" element={<AgentSettings />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  );
}
