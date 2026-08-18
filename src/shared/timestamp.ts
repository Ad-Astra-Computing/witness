/**
 * Strict RFC 3339 timestamp parsing.
 *
 * `new Date(value)` accepts far more than RFC 3339 (date-only, no zone, a space
 * instead of `T`) and silently rolls out-of-range calendar values over
 * (`2026-02-29` becomes March 1). A transport signature whose freshness check
 * used that parse would admit timestamps an independent verifier rejects, and
 * would treat two different strings as the same instant. This parser accepts
 * only a complete, in-range RFC 3339 date-time and returns whole milliseconds
 * since the epoch.
 *
 * The accept/reject table is pinned against the INK protocol by
 * `test/ink-parity.test.ts`.
 */

// Date, uppercase `T`, time with seconds, optional dot-separated fraction, and
// either `Z` or a numeric offset. A comma fraction separator is not accepted.
const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/** Bounds the work done before the regex runs. */
export const MAX_TIMESTAMP_LENGTH = 64;

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return DAYS_IN_MONTH[month - 1] ?? 31;
}

/**
 * Parse a strict RFC 3339 date-time to whole milliseconds since the epoch, or
 * null if it is not well-formed and in range. Sub-millisecond digits are
 * floored into the containing millisecond so the result matches a
 * millisecond-normalized parse elsewhere.
 */
export function parseTimestampMs(value: unknown): number | null {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_TIMESTAMP_LENGTH) {
    return null;
  }
  const m = RFC3339.exec(value);
  if (m === null) return null;

  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  const fraction = m[7];
  const offsetSign = m[8];

  // Validate every component explicitly: Date.UTC would roll an out-of-range
  // value over to the next valid instant instead of rejecting it.
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(year, month)) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  let offsetMinutes = 0;
  if (offsetSign !== undefined) {
    const offsetHour = Number(m[9]);
    const offsetMinute = Number(m[10]);
    if (offsetHour > 23 || offsetMinute > 59) return null;
    offsetMinutes = (offsetSign === "+" ? 1 : -1) * (offsetHour * 60 + offsetMinute);
  }

  // Slice the fraction rather than rounding a float, so the millisecond floor
  // is exact and identical across implementations.
  const fractionMs = fraction ? Number(`${fraction}000`.slice(0, 3)) : 0;
  // setUTCFullYear, not Date.UTC(year, ...), because Date.UTC maps years 0..99
  // to 1900..1999 and would disagree with a verifier that takes the literal
  // four-digit year.
  const d = new Date(Date.UTC(2000, month - 1, day, hour, minute, second));
  d.setUTCFullYear(year);
  const ms = d.getTime() + fractionMs - offsetMinutes * 60_000;
  if (!Number.isFinite(ms)) return null;
  return ms;
}

/** Whether a value is a well-formed strict RFC 3339 timestamp. */
export function isValidTimestamp(value: unknown): boolean {
  return parseTimestampMs(value) !== null;
}
