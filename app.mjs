import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";
import cookieParser from "cookie-parser";
import createError from "http-errors";

import logger from "./middlewares/pino-http.mjs";

import { config } from "dotenv";

import indexRouter from "./routes/index.mjs";
import usersRouter from "./routes/users.mjs";

config();

let app = express();

const __dirname = dirname(fileURLToPath(import.meta.url));

// view engine setup
app.set("views", __dirname + "/views");
app.set("view engine", "hbs");

app.use(logger);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(__dirname + "/public"));

app.use("/", indexRouter);
app.use("/users", usersRouter);

// catch 404 and forward to error handler
app.use((_1, _2, next) => {
  next(createError(404));
});

export default app;
