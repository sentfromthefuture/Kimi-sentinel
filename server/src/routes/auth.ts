import { Router } from "express";
import crypto from "node:crypto";
import { z } from "zod";
import { prisma } from "../db.js";
import { hashToken, randomToken } from "../lib/crypto.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { rateLimit } from "../middleware/rateLimit.js";

export const authRouter = Router();

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(":");
  const candidate = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(candidate));
}

const credsSchema = z.object({
  email: z.string().email().max(200),
  password: z.string().min(8).max(200),
});

const loginLimiter = rateLimit({ windowMs: 60_000, max: 10, key: (req) => `login:${req.ip}` });

authRouter.post("/register", loginLimiter, async (req, res) => {
  const parsed = credsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Valid email and password (8+ chars) required" });
  const { email, password } = parsed.data;
  const exists = await prisma.user.findUnique({ where: { email } });
  if (exists) return res.status(409).json({ error: "Account already exists" });
  const user = await prisma.user.create({ data: { email, passwordHash: hashPassword(password) } });
  await createSession(res, user.id);
  res.json({ id: user.id, email: user.email });
});

authRouter.post("/login", loginLimiter, async (req, res) => {
  const parsed = credsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid credentials format" });
  const user = await prisma.user.findUnique({ where: { email: parsed.data.email } });
  if (!user || !verifyPassword(parsed.data.password, user.passwordHash))
    return res.status(401).json({ error: "Invalid email or password" });
  await createSession(res, user.id);
  res.json({ id: user.id, email: user.email });
});

authRouter.post("/logout", async (req, res) => {
  const token = req.cookies?.sentinel_session;
  if (token) await prisma.session.deleteMany({ where: { tokenHash: hashToken(token) } });
  res.clearCookie("sentinel_session");
  res.json({ ok: true });
});

authRouter.get("/me", requireAuth, async (req: AuthedRequest, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.userId! }, select: { id: true, email: true } });
  res.json(user);
});

async function createSession(res: any, userId: string) {
  const token = randomToken(32);
  await prisma.session.create({
    data: { tokenHash: hashToken(token), userId, expiresAt: new Date(Date.now() + 7 * 86400_000) },
  });
  res.cookie("sentinel_session", token, {
    httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 86400_000, path: "/",
  });
}
