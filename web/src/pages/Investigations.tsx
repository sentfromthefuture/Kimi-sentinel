import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, sevColor, SEV } from "../api";

const STATUS_COLOR: any = { NEW: "bg-gray-800", INVESTIGATING: "bg-yellow-900 text-yellow-300",
  CONTAINED: "bg-green-900 text-green-300", AWAITING_APPROVAL: "bg-orange-900 text-orange-300",
  RESOLVED: "bg-green-900 text-green-300", FALSE_POSITIVE: "bg-gray-700" };

export default function Investigations() {
  const [websites, setWebsites] = useState<any[]>([]); const [websiteId, setWebsiteId] = useState(""); const [incidents, setIncidents] = useState<any[]>([]);
  useEffect(() => { api("/api/websites").then((ws) => { setWebsites(ws); if (ws[0]) setWebsiteId(ws[0].id); }); }, []);
  useEffect(() => { websiteId && api(`/api/websites/${websiteId}/incidents`).then(setIncidents); }, [websiteId]);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3"><h1 className="text-2xl font-bold">Investigations</h1>
        <select className="input max-w-64" value={websiteId} onChange={(e) => setWebsiteId(e.target.value)}>
          {websites.map((w) => <option key={w.id} value={w.id}>{w.hostname}</option>)}</select></div>
      <div className="card">
        {incidents.map((i) => (
          <Link key={i.id} to={`/investigations/${i.id}`} className="block py-2 border-b border-ink-700 hover:bg-ink-700 px-2">
            <div className="flex gap-2 items-center text-sm">
              <span className={sevColor(i.severity)}>{SEV[i.severity]}</span>
              <b>{i.title}</b>
              <span className={`badge ml-auto ${STATUS_COLOR[i.status]}`}>{i.status}</span>
            </div>
            <div className="text-xs text-gray-500">
              {new Date(i.startedAt).toLocaleString()} - {i.investigations[0]?.classification ?? "unclassified"} - actions: {i.actions.length}
            </div>
          </Link>))}
        {incidents.length === 0 && <p className="text-sm text-gray-500">No incidents. Run a demo scenario from Live Activity.</p>}
      </div>
    </div>);
}
