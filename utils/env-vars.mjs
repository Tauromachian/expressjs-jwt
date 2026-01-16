const { logger } = require("./logger");

/**
 * Search for the env variable provided as an argument. If the variable doesn't exist it throws an error.
 * @param {string[]} environmentVariables - The array of environment variables names.
 * @throws {Error} - If the env variable doesn't exist.
 */
export function enforceEnvironmentVariables(environmentVariables) {
  for (const variable of environmentVariables) {
    if (!process.env[variable]) {
      const errMessage = `The ${variable} environment variable is required`;
      console.error(errMessage);
      console.trace();
      throw new Error(errMessage);
    }
  }
}

/**
 * Warn and print trace if the environment variable hasn't been set
 * @param {string} environmentVariable - The env variable to warn about
 * @param {string} defaultValue - The default value that is going to be used
 */
export function warnEnvironmentVariable(environmentVariable, defaultValue) {
  if (!process.env[environmentVariable]) {
    const warnMessage = `The ${environmentVariable} environment is'nt set. 
                        Defaulting to: <<${defaultValue}>>`;

    logger.info(warnMessage);
    logger.trace();
  }
}
