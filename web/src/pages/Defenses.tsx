import { useEffect, useState } from "react";
import { api } from "../api";

export default function Defenses() {
  const [websites, setWebsites] = useState<any[]>([]); const [websiteId, setWebsiteId] = useState("");
  const [actions, setActions] = useState<any[]>([]);
  const load = () => { api("/api/websites").then((ws) => { setWebsites(ws); if (!websiteId && ws[0]) setWebsiteId(ws[0].id); });
    if (websiteId) api(`/api/websites/${websiteId}/actions`).then(setActions).catch(() => {}); };
  useEffect(() => { load(); }, [websiteId]);
  const approve = async (id: string) => { await api(`/api/actions/${id}/approve`, { method: "POST" }); load(); };
  const deny = async (id: string) => { await api(`/api/actions/${id}/deny`, { method: "POST" }); load(); };
  const rollback = async (id: string) => { await api(`/api/actions/${id}/rollback`, { method: "POST" }); load(); };
  const eStop = async (on: boolean) => { await api(`/api/websites/${websiteId}/emergency-stop`, { method: "POST", body: JSON.stringify({ on }) }); load(); };
  const site = websites.find((w) => w.id === websiteId);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <h1 className="text-2xl font-bold">Active Defenses</h1>
        <select className="input max-w-64" value={websiteId} onChange={(e) => setWebsiteId(e.target.value)}>
          {websites.map((w) => <option key={w.id} value={w.id}>{w.hostname}</option>)}</select>
        {site && <button className={site.emergencyStop ? "btn" : "btn-danger"}
          onClick={() => eStop(!site.emergencyStop)}>
          {site.emergencyStop ? "Resume automated defenses" : "EMERGENCY STOP"}</button>}
      </div>
      {site?.emergencyStop && <div className="card border-red-800 text-red-400 text-sm">
        Emergency stop active: all automated defensive actions are suspended. Monitoring and audit logging continue.</div>}
      <div className="card">
        <h2 className="font-semibold mb-2">Approval queue</h2>
        {actions.filter((a) => a.status === "AWAITING_APPROVAL").map((a) => (
          <div key={a.id} className="text-sm py-2 border-b border-ink-700 flex items-center gap-2 flex-wrap">
            <span className="badge bg-orange-900 text-orange-300">{a.type}</span>
            <span>{a.target}</span><span className="text-gray-500">- {a.reason}</span>
            <span className="ml-auto flex gap-2">
              <button className="btn" onClick={() => approve(a.id)}>Approve & execute</button>
              <button className="btn-danger" onClick={() => deny(a.id)}>Deny</button></span>
          </div>))}
        {actions.filter((a) => a.status === "AWAITING_APPROVAL").length === 0 &&
          <p className="text-sm text-gray-500">Nothing awaiting approval.</p>}
      </div>
      <div className="card">
        <h2 className="font-semibold mb-2">Action history</h2>
        {actions.map((a) => (
          <div key={a.id} className="text-sm py-1.5 border-b border-ink-700 flex items-center gap-2">
            <span className="badge bg-ink-700">{a.status}</span><b>{a.type}</b> {a.target}
            <span className="text-xs text-gray-500">expires {a.expiresAt ? new Date(a.expiresAt).toLocaleString() : "n/a"}</span>
            {["CONFIRMED", "APPROVED"].includes(a.status) &&
              <button className="btn ml-auto text-xs" onClick={() => rollback(a.id)}>Rollback now</button>}
          </div>))}
      </div>
    </div>);
}
