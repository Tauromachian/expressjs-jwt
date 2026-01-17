import z from "zod";
import { eq } from "drizzle-orm";
import bcrypt from "bcrypt";

import db from "../db/index.mjs";
import { usersTable } from "../db/schema/user.mjs";

export const loginDto = z
  .object({
    email: z.email(),
    password: z.string().min(8).max(30),
  })
  .superRefine(async (val, ctx) => {
    const results = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.email, val.email));

    const user = results[0];

    if (!user) {
      ctx.addIssue({
        code: "custom",
        path: ["email"],
        message: "User not found",
      });
      return;
    }

    if (!user?.emailverified) {
      ctx.addIssue({
        code: "custom",
        path: ["email"],
        message: "Email not verified",
      });

      return;
    }

    const isPasswordMatch = await bcrypt.compare(val.password, user.password);
    if (!isPasswordMatch) {
      ctx.addIssue({
        code: "custom",
        path: ["password"],
        message: "Incorrect password",
      });

      return;
    }
  });
