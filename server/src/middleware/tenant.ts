import type { Response, NextFunction } from "express";
import { prisma } from "../db.js";
import type { AuthedRequest } from "./auth.js";

// Hard tenant isolation: every website-scoped route re-checks ownership.
export async function requireWebsiteAccess(req: AuthedRequest, res: Response, next: NextFunction) {
  const websiteId = req.params.websiteId ?? req.body?.websiteId;
  if (!websiteId || !req.userId) return res.status(400).json({ error: "websiteId required" });
  const website = await prisma.website.findFirst({ where: { id: websiteId, userId: req.userId } });
  if (!website) return res.status(404).json({ error: "Website not found" });
  (req as any).website = website;
  next();
}
