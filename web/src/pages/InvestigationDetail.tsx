import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, sevColor, SEV } from "../api";

export default function InvestigationDetail() {
  const { id } = useParams(); const [incident, setIncident] = useState<any>(null);
  const load = () => api(`/api/incidents/${id}`).then(setIncident);
  useEffect(() => { load(); }, [id]);
  if (!incident) return null;
  const inv = incident.investigations[0];
  const setStatus = async (status: string) => { await api(`/api/incidents/${incident.id}`, { method: "PATCH", body: JSON.stringify({ status }) }); load(); };
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold">{incident.title}</h1>
        <span className={sevColor(incident.severity)}>{SEV[incident.severity]}</span>
        <span className="badge bg-ink-700">{incident.status}</span>
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="font-semibold mb-2">AI assessment {inv && <span className="text-xs text-gray-500">(provider: {inv.aiProvider})</span>}</h2>
          {inv && (<>
            <p className="text-sm">{inv.explanation}</p>
            <p className="text-sm mt-2">Classification: <b className={inv.classification === "confirmed_threat" ? "text-red-400" : "text-yellow-400"}>{inv.classification}</b> - Confidence: {inv.confidence}</p>
            {inv.recommendedAction && <p className="text-sm mt-1">Recommended action: <b className="text-cyan-400">{inv.recommendedAction}</b></p>}
          </>)}
          <div className="mt-3 flex gap-2">
            {["RESOLVED", "FALSE_POSITIVE"].map((s) => (
              <button key={s} className="btn" onClick={() => setStatus(s)}>Mark {s.replace("_", " ")}</button>))}
          </div>
        </div>
        <div className="card">
          <h2 className="font-semibold mb-2">Defensive actions</h2>
          {incident.actions.map((a: any) => (
            <div key={a.id} className="text-sm py-1 border-b border-ink-700">
              <b>{a.type}</b> on {a.target ?? "-"} - <span className="badge bg-ink-700">{a.status}</span>
              <div className="text-xs text-gray-500">{a.reason}</div>
              {a.approval?.status === "PENDING" && <div className="text-xs text-orange-400">Awaiting your approval (see Active Defenses)</div>}
            </div>))}
          {incident.actions.length === 0 && <p className="text-sm text-gray-500">None taken.</p>}
        </div>
      </div>
      <div className="card">
        <h2 className="font-semibold mb-2">Event timeline</h2>
        {incident.events.map((e: any) => (
          <div key={e.id} className="text-sm py-1 border-b border-ink-700">
            <span className="text-gray-500 text-xs mr-2">{new Date(e.receivedAt).toLocaleTimeString()}</span>
            <span className={`badge mr-2 ${e.source === "SIMULATED" ? "bg-purple-900 text-purple-300" : "bg-green-900 text-green-300"}`}>{e.source}</span>
            {e.type} - {e.sourceIp}
          </div>))}
      </div>
    </div>);
}
