import dns from "node:dns/promises";
import { prisma } from "../db.js";
import { randomToken } from "../lib/crypto.js";
import { audit } from "../lib/audit.js";

// Ownership verification. A URL alone grants nothing.
export async function createVerification(websiteId: string, method: "DNS_TXT" | "FILE") {
  const token = `sentinel-verify=${randomToken(16)}`;
  const verification = await prisma.verification.create({
    data: { websiteId, method, token },
  });
  return {
    verification,
    instructions:
      method === "DNS_TXT"
        ? `Add a DNS TXT record on the root domain: name=_sentinel, value="${token}"`
        : `Create a file at https://<your-domain>/.well-known/sentinel-verify.txt containing exactly: ${token}`,
  };
}

export async function checkVerification(verificationId: string, websiteId: string, baseUrl: string) {
  const v = await prisma.verification.findFirst({ where: { id: verificationId, websiteId } });
  if (!v) throw new Error("Verification not found");
  if (v.status === "VERIFIED") return v;

  let ok = false;
  try {
    if (v.method === "DNS_TXT") {
      const records = await dns.resolveTxt(await websiteIdHostname(websiteId));
      ok = records.some((rec) => rec.join("").includes(v.token));
    } else {
      // Fetch the well-known file over HTTPS only, with strict size limit.
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      try {
        const res = await fetch(`${baseUrl}/.well-known/sentinel-verify.txt`, {
          signal: controller.signal,
          redirect: "error",
          headers: { "user-agent": "SentinelAI-Verifier/0.1" },
        });
        const body = await res.text();
        ok = res.ok && body.trim() === v.token && body.length < 256;
      } finally {
        clearTimeout(timer);
      }
    }
  } catch {
    ok = false;
  }

  if (ok) {
    const updated = await prisma.$transaction(async (tx) => {
      const verified = await tx.verification.update({
        where: { id: v.id }, data: { status: "VERIFIED", verifiedAt: new Date() },
      });
      await tx.website.update({ where: { id: websiteId }, data: { status: "ACTIVE" } });
      return verified;
    });
    await audit(`user:${websiteId}`, "website.verified", websiteId, { method: v.method });
    return updated;
  }
  return prisma.verification.update({ where: { id: v.id }, data: { status: "FAILED" } });
}

// We store hostname on the website row; look it up lazily to avoid a second param.
import { prisma as db } from "../db.js";
async function websiteIdHostname(websiteId: string): Promise<string> {
  const w = await db.website.findUniqueOrThrow({ where: { id: websiteId } });
  return w.hostname;
}
