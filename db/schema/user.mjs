import { sql } from "drizzle-orm";
import {
  boolean,
  integer,
  pgTable,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  email: varchar({ length: 255 }).notNull().unique(),
  verified: boolean().default(sql`FALSE`),
  verificationToken: varchar({ length: 255 }),
  verificationTokenExpires: timestamp(),
  password: varchar({ length: 255 }).notNull(),
});
