import { Router } from "express";
import jwt from "jsonwebtoken";
import { Resend } from "resend";
import bcrypt from "bcrypt";
import { v4 } from "uuid";
import { eq } from "drizzle-orm";

import db from "../db/index.mjs";
import { usersTable } from "../db/schema/user.mjs";

import { authDto } from "../dtos/auth.dto.mjs";
import { castDaysToMilliseconds, castDaysToSeconds } from "../utils/date.mjs";
import { valkeyClient } from "../config/valkey.mjs";

export const authRouter = Router();

const {
  APP_URL,
  NODE_ENV,
  JWT_ACCESS_SECRET,
  JWT_ACCESS_EXPIRES_IN,
  JWT_REFRESH_SECRET,
  JWT_REFRESH_EXPIRES_IN,
  RESEND_API_KEY,
  RESEND_FROM_ADDRESS,
} = process.env;

const resend = new Resend(RESEND_API_KEY);

function makeToken(payload, secret, expiresIn) {
  const accessToken = jwt.sign(payload, secret, {
    expiresIn: expiresIn,
  });

  return accessToken;
}

function makeAccessToken(payload) {
  return makeToken(payload, JWT_ACCESS_SECRET, JWT_ACCESS_EXPIRES_IN);
}

function makeRefreshToken() {
  return makeToken({}, JWT_REFRESH_SECRET, JWT_REFRESH_EXPIRES_IN);
}

async function sendVerifyEmail(urlId, email) {
  const resend = new Resend(RESEND_API_KEY);

  return await resend.emails.send({
    from: `Wildin <${RESEND_FROM_ADDRESS}>`,
    to: [email],
    subject: "Verify your account",
    html: `
            <p>Click the link to verify your account</p>
            <a href="${APP_URL}auth/verify-account/${urlId}">Verify Account</a>
        `,
    replyTo: "onboarding@resend.dev",
  });
}

authRouter.post("/login", async (req, res, next) => {
  if (req?.cookies?.refreshToken) {
    return refresh(req, res, next);
  }

  try {
    var { email } = await authDto.login.parseAsync(req.body);
  } catch (error) {
    error.statusCode = 400;
    return next(error);
  }

  const results = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email));

  if (!results.length) return next("No user found with that email");

  const user = results[0];

  const accessToken = makeAccessToken({
    id: user.id,
    email: user.email,
  });
  const refreshToken = makeRefreshToken();

  const sessionValues = {
    userId: user.id,
    refreshToken,
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
  };

  var result = await valkeyClient.set(
    `session:${sessionValues["refreshToken"]}`,
    JSON.stringify(sessionValues),
    "EX",
    castDaysToSeconds(7),
  );
  if (result !== "OK") throw new Error("Issue with Valkey");

  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      maxAge: castDaysToMilliseconds(7),
    })
    .json({ accessToken: accessToken });
});

authRouter.post("/logout", async (req, res, next) => {
  const token = req.cookies.refreshToken;

  if (!token) {
    const error = new Error("Missing refresh token");
    error.statusCode = 400;
    return next(error);
  }

  await valkeyClient.del(`session:${token}`);

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: NODE_ENV === "production",
    maxAge: castDaysToMilliseconds(7),
  });

  res.json({ message: "Logged out successfully" });
});

authRouter.post("/register", async (req, res, next) => {
  try {
    var { password, email } = await authDto.register.parseAsync(req.body);
  } catch (error) {
    error.statusCode = 400;
    return next(error);
  }

  const SALT_ROUNDS = 10;
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  const newUser = {
    password: hashedPassword,
    email,
  };

  await db.insert(usersTable).values(newUser);

  const { error } = sendVerifyEmail(newUser.urlId, email);
  if (error) next(error);

  res.status(201).json({
    message: "User successfully registered. Please confirm your email.",
  });
});

authRouter.get("/verify", async (req, res) => {
  const { verificationToken } = req.params;

  const results = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.verificationToken, verificationToken));

  const user = results[0];

  if (user.emailverified) {
    return res.json({ message: "User is already verified" });
  }

  await db.update().set(usersTable.verified, true);

  res.status(200).end();
});

authRouter.post("/forgot-password", async (req, res, next) => {
  try {
    var email = z.email().parse(req.body.email);
  } catch (error) {
    error.statusCode = 400;
    return next(error);
  }

  const results = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email));

  const user = results[0];
  if (!user) return next({ statusCode: 401 });

  const token = crypto.randomUUID();

  valkeyClient.set(
    `password-reset-${user.id}`,
    token,
    "EX",
    castDaysToSeconds(1),
  );

  try {
    return await resend.emails.send({
      from: `Wildin <${RESEND_FROM_ADDRESS}>`,
      to: [email],
      subject: "Reset password",
      html: `
            <p>Click the link to reset your password</p>
            <a href="${FRONT_END_URL}/reset-password/${token}">Reset Password</a>
        `,
      replyTo: "onboarding@resend.dev",
    });
  } catch (error) {
    next(error);
  }

  res.status(200).end();
});

async function resetPassword(req, res, next) {
  const { token, password } = req.body;

  try {
    authDto.passwordValidator.parse(password);
  } catch (error) {
    error.statusCode = 400;
    return next(error);
  }

  const result = await repositories.passwordResetToken.find({ token });
  if (!result.success) return next(result.error);

  const passwordResetToken = result.results[0];
  if (!passwordResetToken) {
    return next({ statusCode: 401 });
  }

  const now = getDateInSeconds();
  if (passwordResetToken.expiresAt <= now) {
    return next({ statusCode: 401 });
  }

  const userResult = await repositories.user.find({
    id: passwordResetToken.userId,
  });
  if (!userResult.success) return next(userResult.error);

  const user = userResult.results[0];
  if (!user) return next({ statusCode: 401 });

  const SALT_ROUNDS = 10;
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  user.password = hashedPassword;

  const updateResult = await repositories.user.update(user);
  if (updateResult.success === false) return next(updateResult.error);

  return res.json("Password reset successfully");
}

function refresh(req, res, next) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) return res.sendStatus(401);

  jwt.verify(refreshToken, JWT_REFRESH_SECRET, async (err) => {
    if (err) return next(err);

    let result = await valkeyClient.get(`session:${refreshToken}`);
    if (!result) throw new Error("Refresh token doesn't exist");

    const session = JSON.parse(result);

    const userId = session.userId;
    const resultUser = await repositories.user.find({ id: userId });
    if (!resultUser.success) return next(resultUser.error);
    const user = resultUser.results[0];
    if (!user) return next({ statusCode: 500, message: "User not found" });

    const tokenPayload = {
      username: user.username,
      id: user.id,
      email: user.email,
    };

    const accessToken = makeAccessToken(tokenPayload);

    return res.json({ accessToken });
  });
}
