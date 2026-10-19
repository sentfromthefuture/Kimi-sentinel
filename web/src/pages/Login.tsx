import { useState } from "react";
import { supabase, supabaseConfigured } from "../supabase";

export default function Login({ onLogin }: { onLogin: (u: any) => void }) {
  const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [info, setInfo] = useState(""); const [mode, setMode] = useState<"login" | "register">("login");
  const submit = async (e: any) => {
    e.preventDefault(); setError(""); setInfo("");
    if (!supabaseConfigured) return setError("Supabase is not configured: set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in .env, then restart npm run dev.");
    if (mode === "register") {
      const { data, error } = await supabase.auth.signUp({ email, password });
      if (error) return setError(error.message);
      if (data.session) onLogin(data.session.user);
      else setInfo("Account created. Check your email to confirm it, then sign in.");
    } else {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) return setError(error.message);
      onLogin(data.user);
    }
  };
  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={submit} className="card w-96 space-y-3">
        <h1 className="text-xl font-bold text-cyan-400">Sentinel AI</h1>
        <p className="text-sm text-gray-500">{mode === "login" ? "Sign in to your command centre" : "Create your account"}</p>
        <input className="input" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input className="input" type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <p className="text-red-400 text-sm">{error}</p>}
        {info && <p className="text-green-400 text-sm">{info}</p>}
        <button className="btn w-full">{mode === "login" ? "Sign in" : "Register"}</button>
        <button type="button" className="text-xs text-cyan-500" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}
        </button>
      </form>
    </div>
  );
}
