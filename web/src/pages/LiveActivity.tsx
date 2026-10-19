import { useEffect, useState } from "react";
import { api, sevColor, SEV } from "../api";

export default function LiveActivity() {
  const [websites, setWebsites] = useState<any[]>([]);
  const [websiteId, setWebsiteId] = useState("");
  const [events, setEvents] = useState<any[]>([]);
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [note, setNote] = useState("");
  useEffect(() => {
    api("/api/websites").then((ws) => { setWebsites(ws); if (ws[0]) setWebsiteId(ws[0].id); });
    api("/api/demo/scenarios").then(setScenarios);
  }, []);
  const load = () => websiteId && api(`/api/websites/${websiteId}/events?take=100`).then(setEvents);
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [websiteId]);
  const runDemo = async (scenario: string) => {
    const r = await api(`/api/websites/${websiteId}/demo`, { method: "POST",
      body: JSON.stringify({ scenario, count: 12 }) });
    setNote(r.label); load();
  };
  const srcBadge = (s: string) => s === "REAL" ? "bg-green-900 text-green-300"
    : s === "SIMULATED" ? "bg-purple-900 text-purple-300" : "bg-blue-900 text-blue-300";
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold">Live Activity</h1>
        <select className="input max-w-64" value={websiteId} onChange={(e) => setWebsiteId(e.target.value)}>
          {websites.map((w) => <option key={w.id} value={w.id}>{w.hostname}</option>)}
        </select>
      </div>
      <div className="card">
        <h2 className="font-semibold mb-2">Demonstration mode <span className="text-xs text-purple-400">- simulated, clearly labelled</span></h2>
        <div className="flex gap-2 flex-wrap">
          {scenarios.map((s) => <button key={s.id} className="btn bg-purple-800 hover:bg-purple-700"
            onClick={() => runDemo(s.id)}>{s.label}</button>)}
        </div>
        {note && <p className="text-xs text-purple-400 mt-2">{note}</p>}
      </div>
      <div className="card">
        <h2 className="font-semibold mb-2">Event feed <span className="text-xs text-gray-500">(updates every 5s; only real events appear as REAL)</span></h2>
        {events.length === 0 && <p className="text-sm text-gray-500">No events yet.</p>}
        {events.map((e) => (
          <div key={e.id} className="text-sm py-1 border-b border-ink-700 flex gap-2 items-center">
            <span className="text-gray-500 text-xs w-20 shrink-0">{new Date(e.receivedAt).toLocaleTimeString()}</span>
            <span className={`badge ${srcBadge(e.source)}`}>{e.source}</span>
            <span className={sevColor(e.severity)}>{SEV[e.severity]}</span>
            <span className="font-mono">{e.type}</span>
            <span className="text-gray-500">{e.sourceIp}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
