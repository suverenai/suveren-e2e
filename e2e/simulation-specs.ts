/**
 * Browser specs that use the PRACTICE CRM / ERP / mailbox as their downstream.
 * A gateway is EITHER in simulation mode OR in production, never both, so these
 * run on a SIMULATION gateway (playwright.simulation.config.ts, which starts the
 * shared stack with SUVEREN_SIMULATION=1); every other spec runs on the
 * production gateway (playwright.config.ts). Run both:
 *
 *   npx playwright test && npx playwright test -c playwright.simulation.config.ts
 *   (or npm run test:browser)
 *
 * A spec that needs a REAL connector (records, calendar, email in Gmail mode, ...) must not be
 * in this list: in simulation mode those are paused.
 */
export const SIMULATION_SPECS = [
  'approval-outcome.spec.ts',
  'approval-panel.spec.ts',
  'au10-request-context.spec.ts',
  'au8-preview-reads.spec.ts',
  'blocked-seen.spec.ts',
  'core-objects.spec.ts',
  'files-connector.spec.ts',
  'journey-5-agent-flow.spec.ts',
  'team-roles-caps.spec.ts',
  'ticket-card-email-body.spec.ts',
];
