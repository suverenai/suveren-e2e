/**
 * The day the gateway's card shows for a VIES check ("checked <day>").
 *
 * The connector stamps the check with its OWN clock, not the VIES answer's requestDate:
 * hap-erp-mcp src/live/local/vies.ts writes `checked_at: at.toISOString()` (a UTC time).
 * The manifest shows it as `{…vies.checked_at|date}`, and the gateway's `|date`
 * (suveren-gateway apps/mcp-server/src/lib/checks.ts) prints that time's UTC day.
 *
 * So the expected day is the UTC day of the moment the connector checked: never
 * "today in Vienna" (TODAY_VIENNA), which is already the next day from 23:00 UTC
 * (22:00 in summer) to midnight UTC.
 */
export function viesCheckedDay(checkedAt: Date | number): string {
  return new Date(checkedAt).toISOString().slice(0, 10);
}
