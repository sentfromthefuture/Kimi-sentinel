import type { Request, Response, NextFunction } from "express";

const buckets = new Map<string, { count: number; reset: number }>();

export function rateLimit(opts: { windowMs: number; max: number; key?: (req: Request) => string }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const k = opts.key?.(req) ?? req.ip ?? "anon";
    const now = Date.now();
    let b = buckets.get(k);
    if (!b || b.reset < now) { b = { count: 0, reset: now + opts.windowMs }; buckets.set(k, b); }
    b.count++;
    if (buckets.size > 10000) buckets.clear(); // crude memory bound
    if (b.count > opts.max) return res.status(429).json({ error: "Rate limit exceeded" });
    next();
  };
}
