import { config } from "dotenv";
import debug from "debug";
import http from "http";

import { initLivereload } from "../config/livereload.mjs";

import app from "../app.mjs";

config();

debug.enable(process.env.DEBUG);
const log = debug("express-bootstrap:server");

const { APP_PORT } = process.env;

const DEFAULT_PORT = 3000;
const DEFAULT_LIVERELOAD_PORT = 35729;

// Normalize a port into a number, string, or false.
function normalizePort(val) {
  let port = Number(val);

  if (Number.isNaN(port)) {
    log(`No port specified in env var APP_PORT. Defaulting to ${DEFAULT_PORT}`);

    return DEFAULT_PORT;
  }

  if (port < 0) {
    log("Invalid port: " + port);

    return DEFAULT_PORT;
  }

  return port;
}

/**
 * Returns an open port
 * @param {object} app - Express app
 * @param {number} port - Env or default port
 * @throws Whatever error the http server detects that is not an EADDRINUSE
 * @returns {Promise<number>} port - Open port
 */
async function getOpenPort(app, port) {
  const mockServer = http.createServer(app);

  function checkPort() {
    mockServer.listen(port);

    return new Promise((resolve, reject) => {
      mockServer.on("error", (error) => {
        if (error.code === "EADDRINUSE") {
          resolve(false);
        } else {
          reject(error);
        }
      });

      mockServer.on("listening", () => {
        mockServer.close(() => resolve(true));
      });
    });
  }

  while (!(await checkPort())) port++;
  return port;
}

// Create HTTP server.
let server = http.createServer(app);

(async function init() {
  let serverPort = normalizePort(APP_PORT);
  serverPort = await getOpenPort(app, serverPort);

  let livereloadPort = await getOpenPort(app, DEFAULT_LIVERELOAD_PORT);

  app.set("port", serverPort);
  initLivereload(app, livereloadPort);

  server.listen(serverPort);
  server.on("error", (error) => onError(error, serverPort));
  server.on("listening", onListening);
})();

// Event listener for HTTP server "error" event.
function onError(error, port) {
  if (error.syscall !== "listen") throw error;

  let bind = typeof port === "string" ? "Pipe " + port : "Port " + port;

  const actionByErrorCode = {
    EACCES: () => log(bind + " requires elevated privileges"),
    EADDRINUSE: () => log(bind + " is already in use"),
  };

  const action = actionByErrorCode[error.code];

  if (!action) throw error;

  action();
  process.exit(1);
}

// Event listener for HTTP server "listening" event.
function onListening() {
  let addr = server.address();
  let bind = typeof addr === "string" ? "pipe " + addr : "port " + addr.port;

  log("Listening on " + bind);
}
