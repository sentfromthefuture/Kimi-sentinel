import { useEffect, useState } from "react";
import { api } from "../api";

const KINDS = ["PUBLIC_MONITOR", "CLOUDFLARE", "WAZUH", "CROWDSEC", "MODSECURITY", "SURICATA", "APP_EVENTS"];

export default function Integrations() {
  const [websites, setWebsites] = useState<any[]>([]); const [websiteId, setWebsiteId] = useState("");
  const [items, setItems] = useState<any[]>([]); const [kind, setKind] = useState("PUBLIC_MONITOR");
  const [creds, setCreds] = useState(""); const [flash, setFlash] = useState("");
  const load = () => { if (websiteId) api(`/api/websites/${websiteId}/integrations`).then(setItems).catch(() => {}); };
  useEffect(() => { api("/api/websites").then((ws) => { setWebsites(ws); if (ws[0]) setWebsiteId(ws[0].id); }); }, []);
  useEffect(() => { load(); }, [websiteId]);
  const connect = async () => {
    setFlash("");
    try {
      const r = await api(`/api/websites/${websiteId}/integrations`, { method: "POST",
        body: JSON.stringify({ kind, credentials: creds ? JSON.parse(creds) : undefined }) });
      setFlash(r.ingestionKey ? `Ingestion key (store now): ${r.ingestionKey}` :
        r.status === "CONNECTED" ? `${kind} connected. Granted scopes: ${JSON.parse(r.scopes ?? "[]").join(", ")}` :
        `${kind} NOT connected: ${r.lastError ?? "health check failed"}. Honest status shown - nothing is fabricated.`);
      setCreds(""); load();
    } catch (e: any) { setFlash(e.message); }
  };
  const health = async (id: string) => { await api(`/api/websites/${websiteId}/integrations/${id}/health`, { method: "POST" }); load(); };
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3"><h1 className="text-2xl font-bold">Integrations</h1>
        <select className="input max-w-64" value={websiteId} onChange={(e) => setWebsiteId(e.target.value)}>
          {websites.map((w) => <option key={w.id} value={w.id}>{w.hostname}</option>)}</select></div>
      <div className="card space-y-2">
        <p className="text-xs text-gray-500">An integration is only "CONNECTED" after a real health check against the provider's API succeeds.
          A URL alone never grants access to logs, firewalls, or application internals.</p>
        <div className="flex gap-2 items-end flex-wrap">
          <select className="input max-w-56" value={kind} onChange={(e) => setKind(e.target.value)}>
            {KINDS.map((k) => <option key={k}>{k}</option>)}</select>
          {kind !== "PUBLIC_MONITOR" && kind !== "APP_EVENTS" &&
            <input className="input flex-1 min-w-64 font-mono" placeholder='{"zoneId":"...","apiToken":"..."}'
              value={creds} onChange={(e) => setCreds(e.target.value)} />}
          <button className="btn" onClick={connect}>Connect</button>
        </div>
        {flash && <p className="text-sm text-cyan-400 break-all">{flash}</p>}
      </div>
      <div className="card">
        {items.map((i) => (
          <div key={i.id} className="py-2 border-b border-ink-700 text-sm flex items-center gap-2">
            <b>{i.kind}</b>
            <span className={`badge ${i.status === "CONNECTED" ? "bg-green-900 text-green-300" : i.status === "ERROR" ? "bg-red-900 text-red-300" : "bg-gray-800"}`}>{i.status}</span>
            <span className="text-xs text-gray-500">scopes: {i.scopes}</span>
            {i.lastError && <span className="text-xs text-red-400">{i.lastError}</span>}
            <button className="btn ml-auto text-xs" onClick={() => health(i.id)}>Health check</button>
          </div>))}
        {items.length === 0 && <p className="text-sm text-gray-500">No integrations yet.</p>}
      </div>
    </div>);
}
