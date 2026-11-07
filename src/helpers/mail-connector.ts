/**
 * The `mail` connector (email-mcp) as the public suite runs it: in its test-mailbox mode on a
 * SIMULATION gateway, from the SHIPPED manifest (content/integrations/mail.json), never an inline copy.
 *
 * The suite has no Gmail account, so everything about email here is proven on the connector's practice
 * mailbox. The Gmail data source (the same connector in live mode, adapter gmail) is proven against a real
 * test account in the Rehearsal (scenarios A3, A14, A16, A17) and by email-mcp's own contract test.
 *
 * A gateway is EITHER in simulation mode OR in production: `mail` in its default (simulated) mode starts
 * on a simulation gateway only.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { ProcessManager } from './process-manager.js';
import { GatewayClient } from './gateway-client.js';

const ROOT = join(import.meta.dirname, '..', '..', '..');
export const MAIL_MANIFEST = join(ROOT, 'suveren-gateway', 'content', 'integrations', 'mail.json');

export function readMailManifest(): any {
  return JSON.parse(readFileSync(MAIL_MANIFEST, 'utf8'));
}

/** A simulation gateway that needs only `mail` (no crm / erp / records auto-provisioned). */
export async function startMailGateway(
  pm: ProcessManager,
  opts: { port: number; spUrl: string; spApiKey: string; profilesDir: string },
): Promise<void> {
  const prev = process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
  process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = '1';
  try {
    await pm.startGateway({ simulation: true, ...opts });
  } finally {
    if (prev === undefined) delete process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    else process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = prev;
  }
}

/** Register the shipped mail manifest as the gateway's integration and wait until it runs. */
export async function addMailConnector(gw: GatewayClient, opts: { readAgeDays?: number } = {}): Promise<void> {
  const mail = readMailManifest();
  await gw.addIntegration({
    id: mail.id,
    name: mail.name,
    command: mail.mcp.command,
    args: mail.mcp.args,
    envKeys: {},
    profile: mail.profile,
    enabled: true,
    toolGating: mail.toolGating,
    npmPackage: mail.npmPackage,
    ...(opts.readAgeDays !== undefined ? { readAgeDays: opts.readAgeDays } : {}),
  } as Parameters<GatewayClient['addIntegration']>[0]);
  await gw.waitForIntegration('mail');
}

export async function callText(client: Client, name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content as Array<{ text?: string }>).map((c) => c.text ?? '').join('\n');
  return { text, isError: result.isError === true };
}

/** A schema-valid practice-mailbox package with the given inbound messages (the MCP SDK validates the tool schema client-side). */
export function practicePackage(name: string, requests: Array<{ id: string; subject: string; body?: string; fromName?: string; fromEmail?: string }>) {
  return {
    name,
    currency: 'EUR',
    customers: [{ name: 'A Customer', credit_limit: 0 }],
    products: [{ sku: 'SKU-1', name: 'Product', list_price: 1, stock: 1 }],
    cases: requests.map((r) => ({
      id: r.id,
      request: { from: { name: r.fromName ?? 'A Customer', email: r.fromEmail ?? 'customer@example.com' }, subject: r.subject, body: r.body ?? 'A question.' },
      reply: { subject: `Re: ${r.subject}`, body: 'An answer.' },
    })),
  };
}
