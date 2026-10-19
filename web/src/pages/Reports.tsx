import { useEffect, useState } from "react";
import { api, sevColor, SEV } from "../api";

export default function Reports() {
  const [websites, setWebsites] = useState<any[]>([]); const [websiteId, setWebsiteId] = useState("");
  const [report, setReport] = useState<any>(null);
  useEffect(() => { api("/api/websites").then((ws) => { setWebsites(ws); if (ws[0]) setWebsiteId(ws[0].id); }); }, []);
  const load = () => websiteId && api(`/api/websites/${websiteId}/report?days=7`).then(setReport);
  useEffect(() => { load(); }, [websiteId]);
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3"><h1 className="text-2xl font-bold">Security Reports</h1>
        <select className="input max-w-64" value={websiteId} onChange={(e) => setWebsiteId(e.target.value)}>
          {websites.map((w) => <option key={w.id} value={w.id}>{w.hostname}</option>)}</select>
        <button className="btn" onClick={load}>Refresh</button></div>
      {report && (<>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="Incidents (7d)" value={report.incidentCount} />
          <Stat label="Unresolved" value={report.unresolved} />
          <Stat label="False positives" value={report.falsePositives} />
          <Stat label="Integration failures" value={report.monitoringFailures} />
        </div>
        <div className="card">
          <h2 className="font-semibold mb-2">Incidents</h2>
          {report.incidents.length === 0 && <p className="text-sm text-gray-500">No incidents in this period.</p>}
          {report.incidents.map((i: any) => (
            <div key={i.id} className="text-sm py-1 border-b border-ink-700">
              <span className={sevColor(i.severity)}>{SEV[i.severity]}</span> <b>{i.title}</b> - {i.status}
              <span className="text-xs text-gray-500"> - {i.classification ?? "n/a"} - actions: {i.actions.map((a: any) => `${a.type}(${a.status})`).join(", ") || "none"}</span>
            </div>))}
        </div>
        <div className="card">
          <h2 className="font-semibold mb-2">Recommendations</h2>
          {report.recommendations.length === 0 && <p className="text-sm text-green-400">No outstanding recommendations.</p>}
          {report.recommendations.map((r: string, i: number) => <p key={i} className="text-sm text-yellow-400">- {r}</p>)}
          <p className="text-xs text-gray-500 mt-2">{report.coverageNote}</p>
        </div>
      </>)}
    </div>);
}
function Stat({ label, value }: any) {
  return <div className="card"><div className="text-2xl font-bold text-cyan-400">{value}</div>
    <div className="text-xs text-gray-500">{label}</div></div>;
}
