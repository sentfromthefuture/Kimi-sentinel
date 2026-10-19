import type { Request, Response, NextFunction } from "express";
import { prisma } from "../db.js";
import { hashToken } from "../lib/crypto.js";

export interface AuthedRequest extends Request { userId?: string; }

export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = req.cookies?.sentinel_session;
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  const session = await prisma.session.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { user: true },
  });
  if (!session || session.expiresAt < new Date()) {
    return res.status(401).json({ error: "Session expired" });
  }
  req.userId = session.userId;
  next();
}
