import { useEffect, useState } from "react";
import { api, sevColor } from "../api";

export default function Overview() {
  const [data, setData] = useState<any>({ websites: [], allDecisions: [], notifications: [] });
  const load = async () => {
    const websites = await api("/api/websites");
    const allDecisions = (await Promise.all(websites.map(async (w: any) =>
      ({ w, decisions: await api(`/api/websites/${w.id}/decisions`).catch(() => []) }))));
    const notifications = await api("/api/notifications").catch(() => []);
    setData({ websites, allDecisions, notifications });
  };
  useEffect(() => { load(); const t = setInterval(load, 10_000); return () => clearInterval(t); }, []);
  const { websites, allDecisions, notifications } = data as any;
  if (!websites) return null;
  const totalEvents = websites.reduce((n: number, w: any) => n + w._count.events, 0);
  const totalIncidents = websites.reduce((n: number, w: any) => n + w._count.incidents, 0);
  const decisions = (allDecisions ?? []).flatMap((x: any) => x.decisions.map((d: any) => ({ ...d, host: x.w.hostname })));

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Overview</h1>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Websites protected" value={websites.length} />
        <Stat label="Security events" value={totalEvents} />
        <Stat label="Incidents opened" value={totalIncidents} />
        <Stat label="Autonomous modes active" value={websites.filter((w: any) => w.operatingMode !== "OBSERVER").length} />
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="font-semibold mb-2">Protected websites</h2>
          {websites.length === 0 && <p className="text-sm text-gray-500">No websites yet. Add one from Protected Websites.</p>}
          {websites.map((w: any) => (
            <div key={w.id} className="flex justify-between py-1.5 border-b border-ink-700 text-sm">
              <span>{w.hostname} <span className="text-xs text-gray-500">({w.protectionLevel})</span></span>
              <span className="flex gap-2 items-center">
                {w.emergencyStop && <span className="badge bg-red-900 text-red-300">E-STOP</span>}
                <span className="badge bg-ink-700">{w.operatingMode}</span>
                <span className={`badge ${w.status === "ACTIVE" ? "bg-green-900 text-green-300" : "bg-yellow-900 text-yellow-300"}`}>{w.status}</span>
              </span>
            </div>
          ))}
        </div>
        <div className="card">
          <h2 className="font-semibold mb-2">Latest agent decisions</h2>
          {decisions.length === 0 && <p className="text-sm text-gray-500">No agent activity yet. Run a demo scenario to see the agent work.</p>}
          {decisions.slice(0, 10).map((d: any) => (
            <div key={d.id} className="py-1 border-b border-ink-700 text-sm">
              <span className="text-gray-500 text-xs">{new Date(d.createdAt).toLocaleTimeString()}</span>{" "}
              <span className={sevColor(d.decision.classification === "confirmed_threat" ? 4 : 2)}>
                {d.decision.classification}
              </span>{" "}
              on {d.host} - {d.decision.recommendedAction}
              <span className="text-xs text-gray-500"> (conf {d.decision.confidence})</span>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <h2 className="font-semibold mb-2">Notifications</h2>
        {(notifications ?? []).length === 0 && <p className="text-sm text-gray-500">No notifications.</p>}
        {(notifications ?? []).slice(0, 10).map((n: any) => (
          <div key={n.id} className={`text-sm py-1 ${n.read ? "text-gray-500" : ""}`}>
            <span className={`badge mr-2 ${n.level === "critical" ? "bg-red-900 text-red-300" : "bg-ink-700"}`}>{n.level}</span>
            {n.message}
          </div>
        ))}
      </div>
    </div>
  );
}
function Stat({ label, value }: any) {
  return <div className="card"><div className="text-2xl font-bold text-cyan-400">{value}</div>
    <div className="text-xs text-gray-500">{label}</div></div>;
}
