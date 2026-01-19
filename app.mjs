import express from "express";
import cookieParser from "cookie-parser";
import createError from "http-errors";

import { config } from "dotenv";

import logger from "./middlewares/pino-http.mjs";

import { jwtRouter } from "./routes/jwt.mjs";
import { googleRouter } from "./routes/google.mjs";
import { errorHandler } from "./middlewares/errorHandler.mjs";

config();

let app = express();

app.use(logger);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use("/auth/jwt", jwtRouter);
app.use("/auth/google", googleRouter);

// catch 404 and forward to error handler
app.use((_1, _2, next) => {
  next(createError(404));
});

app.use(errorHandler);

export default app;
