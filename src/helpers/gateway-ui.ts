/**
 * Gateway UI helpers shared by the browser tests — written to work against
 * both the core-objects UI (UI spec §12: approvals and tickets are rows that
 * open in place) and older gateways (every card rendered open).
 */
import type { Locator, Page } from 'playwright';

/**
 * Waits until the approval panel is not sliding. The gateway marks a slide with `apr-has-anim` on <body> for its
 * duration (ApprovalPanelHost: SLIDE_MS + 80 ms). Two checks a frame apart, because a route change starts the slide
 * in an effect just after the URL changes. Older gateways without the class pass at once.
 */
export async function waitForPanelStill(page: Page, timeout = 5_000): Promise<void> {
  const still = () => document.body ? !document.body.classList.contains('apr-has-anim') : true;
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await page.evaluate(still).catch(() => true)) {
      await page.waitForTimeout(100);
      if (await page.evaluate(still).catch(() => true)) return;
    }
    await page.waitForTimeout(50);
  }
}

/**
 * The approval card for `proposalId` on the Approvals page, opened (approval
 * card v3, UI spec §17). Rows in the list carry `data-proposal-id`; the open
 * card is `[data-testid="approval-card"][data-proposal-id]`. From another open
 * card it goes back to the list first. Older gateways: the row that opens in
 * place, or the card that prints "Proposal: <id>".
 */
export async function openApprovalById(page: Page, proposalId: string, timeout = 30_000): Promise<Locator> {
  // The approval panel holds one card per approval "for me", with Previous / Next;
  // after "Later" it is a strip, and a list row opens it (approval panel, PR #185).
  const panel = page.getByTestId('approval-panel');
  const card = panel.locator(`[data-testid="approval-card"][data-proposal-id="${proposalId}"]`);
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    // The panel may still be sliding: it opens by itself on one page, and going to another page sends it away
    // (ApprovalPanelHost). A card seen mid-slide is gone a moment later (CI 45102801215: the card was found, then
    // "outside of the viewport", then detached). Look only once the panel is still.
    await waitForPanelStill(page);
    if (await card.isVisible().catch(() => false)) return card;
    const open = (await panel.getAttribute('aria-hidden').catch(() => 'true')) === 'false';
    if (open) {
      const prev = page.getByTestId('approval-prev');
      const next = page.getByTestId('approval-next');
      for (let i = 0; i < 50 && (await prev.isEnabled().catch(() => false)); i++) await prev.click();
      for (let i = 0; i < 50; i++) {
        if (await card.isVisible().catch(() => false)) return card;
        if (!(await next.isEnabled().catch(() => false))) break;
        await next.click();
        await page.waitForTimeout(300);
      }
    } else {
      const strip = page.getByTestId('approval-strip-open');
      const head = page.locator(`[data-testid="approval-row"][data-proposal-id="${proposalId}"] .appr-item-head`);
      if (await strip.isVisible().catch(() => false)) await strip.click();
      else if (await head.count()) await head.click();
    }
    await page.waitForTimeout(400);
  }
  throw new Error(`No approval ${proposalId} in the approval panel`);
}

/** Tickets page: open every ticket row so each full record is rendered. */
export async function openAllTickets(page: Page): Promise<void> {
  const heads = page.locator('.ticket-obj-card:not(.is-open) .ticket-obj-head');
  for (let guard = 0; guard < 200 && (await heads.count()) > 0; guard++) {
    await heads.first().click();
  }
}

/**
 * On the Approvals page (a list only) show the first waiting approval in the
 * approval panel: a row opens it. Returns once the panel is open. (An approval
 * panel that is already open - it opens by itself on other pages - is left alone.)
 */
export async function openFirstApprovalInPanel(page: Page): Promise<void> {
  const panel = page.getByTestId('approval-panel');
  const head = page.locator('[data-testid="approval-row"] .appr-item-head').first();
  const shown = panel.locator('[data-testid="approval-card"]').filter({ visible: true }).first();
  await head.or(shown).first().waitFor({ timeout: 30_000 });
  // The panel can open by itself on the page before (the dashboard after sign-in) and leave on the move here: a card seen
  // in it at that moment is on its way out (ApprovalPanelHost closes it on a route change). Decide only once it stands still.
  // (e2e 45132219585 and 45146535249: the card was gone, "sealed-values" never found.)
  await waitForPanelStill(page);
  if (!(await shown.isVisible()) || (await panel.getAttribute('aria-hidden')) !== 'false') {
    await head.click({ timeout: 10_000 });
    await waitForPanelStill(page);
  }
  await shown.waitFor({ state: 'visible', timeout: 20_000 });
}
