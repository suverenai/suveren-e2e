/**
 * The day the gateway's card shows for a VIES check ("checked <day>").
 *
 * The connector stamps the check with its OWN clock, not the VIES answer's requestDate:
 * hap-erp-mcp src/live/local/vies.ts writes `checked_at: at.toISOString()` (a UTC time).
 * The manifest shows it as `{…vies.checked_at|date}`, and the gateway's `|date`
 * (suveren-gateway apps/mcp-server/src/lib/checks.ts, fix/check-date-local) prints that
 * time's day in the time zone of the computer the gateway runs on: the person's own day.
 *
 * The suite starts the gateway on this computer, so the expected day is the local day of
 * the moment the connector checked, in this process's time zone (TZ) — never the UTC day,
 * which in Vienna is still yesterday from 00:00 to 01:00 (02:00 in summer).
 */
export function viesCheckedDay(checkedAt: Date | number): string {
  const d = new Date(checkedAt);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
