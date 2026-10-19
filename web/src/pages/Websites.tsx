import { useEffect, useState } from "react";
import { api } from "../api";

export default function Websites() {
  const [websites, setWebsites] = useState<any[]>([]);
  const [url, setUrl] = useState(""); const [name, setName] = useState("");
  const [error, setError] = useState(""); const [verifyInfo, setVerifyInfo] = useState<any>(null);
  const [baseline, setBaseline] = useState<any>(null);
  const load = () => api("/api/websites").then(setWebsites);
  useEffect(() => { load(); }, []);

  const add = async (e: any) => {
    e.preventDefault(); setError(""); setVerifyInfo(null); setBaseline(null);
    try { await api("/api/websites", { method: "POST", body: JSON.stringify({ url, name }) }); setUrl(""); setName(""); load(); }
    catch (err: any) { setError(err.message); }
  };
  const startVerify = async (w: any, method: "DNS_TXT" | "FILE") => {
    const r = await api(`/api/websites/${w.id}/verification`, { method: "POST", body: JSON.stringify({ method }) });
    setVerifyInfo({ websiteId: w.id, verificationId: r.verification.id, instructions: r.instructions });
  };
  const checkVerify = async () => {
    const r = await api(`/api/websites/${verifyInfo.websiteId}/verification/${verifyInfo.verificationId}/check`, { method: "POST" });
    if (r.status === "VERIFIED") { setVerifyInfo(null); setError(""); load(); } else setError("Verification not detected yet. Status: " + (r.status ?? "unknown"));
  };
  const runBaseline = async (w: any) => {
    setError("");
    try { setBaseline(await api(`/api/websites/${w.id}/baseline`, { method: "POST" })); }
    catch (err: any) { setError(err.message); }
  };

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Protected Websites</h1>
      <form onSubmit={add} className="card flex gap-2 items-end flex-wrap">
        <div className="flex-1 min-w-48"><label className="text-xs text-gray-500">URL</label>
          <input className="input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" /></div>
        <div className="flex-1 min-w-40"><label className="text-xs text-gray-500">Name (optional)</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
        <button className="btn">Protect a Website</button>
      </form>
      <p className="text-xs text-gray-500 max-w-2xl">A URL alone grants no permissions. Ownership verification is required before any monitoring.
        Private IPs, localhost, link-local and cloud-metadata destinations are rejected outright.</p>
      {error && <div className="card text-red-400 text-sm">{error}</div>}
      {verifyInfo && (
        <div className="card border-cyan-800">
          <h2 className="font-semibold">Verify ownership</h2>
          <p className="text-sm mt-1">{verifyInfo.instructions}</p>
          <button className="btn mt-3" onClick={checkVerify}>I've done this - check now</button>
        </div>
      )}
      {baseline && (
        <div className="card">
          <h2 className="font-semibold mb-2">Baseline assessment findings</h2>
          <p className="text-xs text-yellow-500 mb-2">{baseline.note}</p>
          {baseline.findings.map((f: any, i: number) => (
            <div key={i} className="text-sm py-1 border-b border-ink-700">
              <span className={`badge mr-2 ${f.status === "pass" ? "bg-green-900 text-green-300" : f.status === "fail" ? "bg-red-900 text-red-300" : "bg-yellow-900 text-yellow-300"}`}>{f.status}</span>
              <b>{f.check}</b> - {f.evidence} <span className="text-xs text-gray-500">(conf: {f.confidence})</span>
              {f.remediation && <div className="text-xs text-cyan-500 ml-14">{f.remediation}</div>}
            </div>
          ))}
        </div>
      )}
      <div className="card">
        {websites.map((w) => (
          <div key={w.id} className="py-2 border-b border-ink-700 flex flex-wrap items-center gap-2">
            <div className="flex-1">
              <b>{w.name}</b> <span className="text-xs text-gray-500">{w.url}</span>
              <div className="text-xs text-gray-500">
                {w.status} - {w.protectionLevel} - mode {w.operatingMode} - last monitored: {w.lastMonitoredAt ? new Date(w.lastMonitoredAt).toLocaleString() : "never"}
              </div>
            </div>
            {w.status !== "ACTIVE" && (<>
              <button className="btn" onClick={() => startVerify(w, "DNS_TXT")}>Verify via DNS</button>
              <button className="btn" onClick={() => startVerify(w, "FILE")}>Verify via file</button>
            </>)}
            {w.status === "ACTIVE" && <button className="btn" onClick={() => runBaseline(w)}>Run baseline check</button>}
          </div>
        ))}
      </div>
    </div>
  );
}
