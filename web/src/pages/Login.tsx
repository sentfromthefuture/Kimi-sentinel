import { useState } from "react";
import { api } from "../api";

export default function Login({ onLogin }: { onLogin: (u: any) => void }) {
  const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [mode, setMode] = useState<"login" | "register">("login");
  const submit = async (e: any) => {
    e.preventDefault(); setError("");
    try { onLogin(await api(`/api/auth/${mode}`, { method: "POST", body: JSON.stringify({ email, password }) })); }
    catch (err: any) { setError(err.message); }
  };
  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={submit} className="card w-96 space-y-3">
        <h1 className="text-xl font-bold text-cyan-400">Sentinel AI</h1>
        <p className="text-sm text-gray-500">{mode === "login" ? "Sign in to your command centre" : "Create your account"}</p>
        <input className="input" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input className="input" type="password" placeholder="Password (8+ chars)" value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <button className="btn w-full">{mode === "login" ? "Sign in" : "Register"}</button>
        <button type="button" className="text-xs text-cyan-500" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}
        </button>
      </form>
    </div>
  );
}
