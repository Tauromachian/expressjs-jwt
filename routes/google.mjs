import { Router } from "express";

import { OAuth2Client } from "google-auth-library";

import crypto from "crypto";

let router = Router();

const { APP_URL, GOOGLE_ID, GOOGLE_SECRET, GOOGLE_STATE_SECRET } = process.env;

const REDIRECT_URI = `${APP_URL}auth/google/callback`;

const googleClient = new OAuth2Client({
  clientId: GOOGLE_ID,
  clientSecret: GOOGLE_SECRET,
  redirectUri: REDIRECT_URI,
});

function makeState() {
  const payload = {
    nonce: crypto.randomBytes(16).toString("hex"),
    iat: Date.now(),
  };

  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const sig = crypto
    .createHmac("sha256", GOOGLE_STATE_SECRET)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${sig}`;
}

function validateState(state) {
  const [encoded, sig] = state.split(".");

  const expectedSig = crypto
    .createHmac("sha256", GOOGLE_STATE_SECRET)
    .update(encoded)
    .digest("base64url");

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
    return false;
  }

  const payload = JSON.parse(Buffer.from(encoded, "base64url").toString());

  const FIVE_MINUTES = 5 * 60 * 1000;
  if (Date.now() - payload.iat > FIVE_MINUTES) return false;

  return true;
}

router.get("/", (_, res) => {
  res.render("index", { title: "Express" });
});

router.get("/auth/google", (_, res) => {
  const params = new URLSearchParams({
    client_id: GOOGLE_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    prompt: "select_account",
    state: makeState(),
  });

  const GOOGLE_URL = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

  return res.redirect(GOOGLE_URL);
});

router.get("/auth/google/callback", async (req, res, next) => {
  const { code, state } = req.query;

  if (!code || !state) return next(new Error("Missing Google credential"));

  const isValid = validateState(state);

  if (!isValid) return next(new Error("Invalid state"));

  try {
    const { tokens } = await googleClient.getToken(String(code));

    if (!tokens.id_token) throw new Error("Error with Google Login`");

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_ID,
    });

    const payload = ticket.getPayload();

    console.log("Logged in successfully");
    console.log(payload);

    return res.redirect(APP_URL);
  } catch (error) {
    return next(error);
  }
});

export default router;
