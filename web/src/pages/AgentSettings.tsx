import { useEffect, useState } from "react";
import { api } from "../api";

export default function AgentSettings() {
  const [websites, setWebsites] = useState<any[]>([]); const [websiteId, setWebsiteId] = useState("");
  const [site, setSite] = useState<any>(null); const [msg, setMsg] = useState("");
  useEffect(() => { api("/api/websites").then((ws) => { setWebsites(ws); if (ws[0]) setWebsiteId(ws[0].id); }); }, []);
  useEffect(() => { websiteId && api(`/api/websites/${websiteId}`).then(setSite).catch(() => setSite(null)); }, [websiteId]);
  const setMode = async (mode: string, level: string) => {
    await api(`/api/websites/${websiteId}/mode`, { method: "PATCH", body: JSON.stringify({ operatingMode: mode, protectionLevel: level }) });
    setMsg("Mode updated by you - the agent can never change its own permissions.");
    api(`/api/websites/${websiteId}`).then(setSite);
  };
  const MODES = [
    ["OBSERVER", "WATCH", "Observer - monitor + investigate + recommend only. Never modifies production."],
    ["GUARDIAN", "GUARDIAN", "Guardian - auto-executes explicitly authorized, reversible actions that pass policy."],
    ["INCIDENT_RESPONSE", "GUARDIAN", "Incident Response - investigates serious incidents; high-impact actions still need your approval."],
  ];
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3"><h1 className="text-2xl font-bold">Agent Settings</h1>
        <select className="input max-w-64" value={websiteId} onChange={(e) => setWebsiteId(e.target.value)}>
          {websites.map((w) => <option key={w.id} value={w.id}>{w.hostname}</option>)}</select></div>
      {msg && <div className="card text-cyan-400 text-sm">{msg}</div>}
      <div className="space-y-2">
        {MODES.map(([m, p, desc]) => (
          <div key={m} className={`card cursor-pointer ${site?.operatingMode === m ? "border-cyan-600" : ""}`} onClick={() => setMode(m, p)}>
            <b>{m}</b>
            <p className="text-sm text-gray-400">{desc}</p>
          </div>))}
      </div>
      <div className="card text-sm text-gray-400">
        Safety guarantees enforced outside the AI model: deterministic policy engine - scope checks -
        allowlist protection - action rate limits - temporary reversible actions with expiry + rollback -
        human approval for high-impact actions - emergency stop - full audit trail. The agent cannot modify these.
      </div>
    </div>);
}
