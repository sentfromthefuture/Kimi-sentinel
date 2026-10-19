import { prisma } from "../db.js";

export async function audit(actor: string, action: string, target: string, meta: unknown = {}) {
  await prisma.auditLog.create({
    data: { actor, action, target, meta: JSON.stringify(meta) },
  });
}
