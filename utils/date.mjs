export function castDaysToMilliseconds(days) {
  const MILLISECONDS_OF_SECOND = 1000;
  const SECONDS_OF_MINUTE = 60;
  const MINUTES_OF_HOUR = 60;
  const HOURS_OF_DAY = 24;

  return (
    days *
    HOURS_OF_DAY *
    MINUTES_OF_HOUR *
    SECONDS_OF_MINUTE *
    MILLISECONDS_OF_SECOND
  );
}

export function castDaysToSeconds(days) {
  const SECONDS_OF_MINUTE = 60;
  const MINUTES_OF_HOUR = 60;
  const HOURS_OF_DAY = 24;

  return days * HOURS_OF_DAY * MINUTES_OF_HOUR * SECONDS_OF_MINUTE;
}

/**
 * Returns date timestamp in seconds
 */
export function getDateInSeconds() {
  return Math.floor(Date.now() / 1000);
}
