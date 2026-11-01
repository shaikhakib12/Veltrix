/**
 * Validates whether a string is a recognized IANA timezone identifier
 * using the standard ECMAScript Internationalization API (Intl.DateTimeFormat).
 *
 * Supported examples: 'America/New_York', 'Europe/London', 'Asia/Tokyo', 'UTC'.
 * Rejects invalid strings such as 'Invalid/Zone', 'Mars/Olympus', or arbitrary numbers.
 */
export function isValidIanaTimezone(timeZone?: string): boolean {
  if (!timeZone || typeof timeZone !== 'string') {
    return false;
  }
  const trimmed = timeZone.trim();
  if (trimmed.length === 0) {
    return false;
  }
  try {
    Intl.DateTimeFormat(undefined, { timeZone: trimmed });
    return true;
  } catch {
    return false;
  }
}
