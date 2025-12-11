import z from "zod";

export const authDto = z
  .object({
    email: z.email(),
    password: z.string().min(8).max(30),
  })
  .superRefine(async (val, ctx) => {
    const result = await userRepo.find({ username: val.username });
    if (!result.success) {
      ctx.addIssue({
        code: "custom",
        path: ["username"],
        message: "DB Error",
      });

      return;
    }

    const user = result.results[0];

    if (!user) {
      ctx.addIssue({
        code: "custom",
        path: ["username"],
        message: "User not found",
      });
      return;
    }

    if (!user?.emailverified) {
      ctx.addIssue({
        code: "custom",
        path: ["username"],
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
