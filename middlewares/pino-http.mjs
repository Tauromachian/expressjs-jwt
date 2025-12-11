import logger from "../utils/logger.mjs";
import pino from "pino-http";

let loggerMiddleware = pino({
  logger,
});

export default loggerMiddleware;
