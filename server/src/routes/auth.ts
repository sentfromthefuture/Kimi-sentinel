import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";

export const authRouter = Router();

// Sign-up, sign-in and sign-out are handled by Supabase Auth in the browser (web/src/supabase.ts).
authRouter.get("/me", requireAuth, (req: AuthedRequest, res) => {
  res.json({ id: req.userId, email: req.userEmail });
});
