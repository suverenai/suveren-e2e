/**
 * Journey 1: First-Time Personal User
 *
 * Registration → API key → gateway login → navigate pages → authorize → revoke → mobile
 *
 * Key constraint: gateway stores API key in React state (no cookies).
 * Each test gets a fresh page, so we must login + do all checks in one test,
 * navigating via sidebar clicks (SPA navigation) not page.goto (full reload).
 */
import { test, expect, ensureUsersRegistered, ALICE, signInToGateway, handleOnboarding, createAuthorization, activateIntegration, SP_URL, GW_URL , ensureProfileEnabledForActiveGroups, latestProfileId, cardTitlePattern} from './fixtures';

// The version the gateway's Records wizard grants under (newest) — see latestProfileId.
const RECORDS_PROFILE = latestProfileId('records');

test.describe.serial('Journey 1: Personal User', () => {
  let apiKey: string;

  test('1.1 Register on SP, get API key', async () => {
    // Reuse the stable ALICE account (registered once in global-setup) rather
    // than minting a fresh user each run. A new account every re-run would
    // collide with the previous account already in the gateway vault and
    // trigger the "different account — wipe local data?" modal. Stable account
    // → no conflict → no wipe.
    await ensureUsersRegistered();
    apiKey = ALICE.apiKey;
    expect(apiKey).toBeTruthy();
    expect(apiKey.length).toBeGreaterThan(10);
  });

  test('1.2 Gateway: login, navigate all pages, check sidebar', async ({ page }) => {
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);

    // Dashboard — wait for page to fully render
    await expect(page.locator('.page-title')).toBeVisible({ timeout: 10_000 });

    // Sidebar items (nav labels from Sidebar.tsx)
    await expect(page.locator('.sidebar')).toBeVisible();
    await expect(page.locator('.sidebar-item:has-text("Connectors")')).toBeVisible();
    await expect(page.locator('.sidebar-item:has-text("Settings")')).toBeVisible();
    await expect(page.locator('.sidebar-item:has-text("Approvals")')).toBeVisible();
    await expect(page.locator('.sidebar-item:has-text("Mandates")')).toBeVisible();

    // Navigate to Connectors (route /integrations) via sidebar — assert the route + page title
    // (card content depends on integrations loading, which is flaky).
    await page.click('.sidebar-item:has-text("Connectors")');
    await page.waitForURL('**/integrations');
    await expect(page.locator('.page-title')).toHaveText('Connectors', { timeout: 10_000 });

    // Navigate to Settings (was "AI Assistant" before suveren-gateway #29)
    await page.click('.sidebar-item:has-text("Settings")');
    await page.waitForURL('**/settings');
    await expect(page.locator('.page-title, h1').first()).toBeVisible({ timeout: 10_000 });

    // Navigate to Approvals (proposals — empty)
    await page.click('.sidebar-item:has-text("Approvals")');
    await page.waitForURL('**/approvals');
    await expect(page.locator('.page-title, h1').first()).toBeVisible({ timeout: 10_000 });

    // Open the authorize picker from the Authorizations page (the dedicated
    // "Authorize" nav item was removed in v0.4).
    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates**');
    await page.click('button:has-text("New mandate")');
    await page.locator('.profile-grid, .card').first().waitFor({ state: 'visible', timeout: 10_000 });
  });

  test('1.3 Gateway: activate integrations', async ({ page }) => {
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);

    // This is a PRODUCTION gateway (simulation OR production, never both): the real
    // connector (Records) runs; the practice CRM, set to simulation by default, is
    // paused and says so. The practice CRM journeys run on the simulation gateway
    // (playwright.simulation.config.ts, journey-5).
    await activateIntegration(page, 'Records');
    await page.waitForLoadState('networkidle');
    await page.click('.sidebar-item:has-text("Connectors")');
    await page.waitForURL('**/integrations');
    const crmCard = page.locator('.card', { has: page.locator('.card-title', { hasText: cardTitlePattern('CRM') }) }).first();
    await crmCard.waitFor({ state: 'visible', timeout: 10_000 });
    // The card says it is paused in production, and why; nothing runs.
    await expect(crmCard).toContainText('Paused in production', { timeout: 30_000 });
    await expect(crmCard).toContainText('This gateway runs in production, and this connector is set to simulation.');
    await expect(crmCard.locator('text=Running')).toHaveCount(0);
  });

  test('1.4 Gateway: create authorization with Automatic commit', async ({ page }) => {
    // The browser suite shares the ALICE account and runs sequentially, so by
    // the time this runs `group-journey` has made a team her active group. A
    // team must have the profile enabled before anyone can grant in it.
    await ensureProfileEnabledForActiveGroups(apiKey, RECORDS_PROFILE, ALICE.id);
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);

    await createAuthorization(page, {
      profileName: 'Records',
      bounds: { write_daily_max: '10' },
      intent: 'Need agent to store research findings and enable persistent knowledge management',
      title: 'Records: research storage',
      commitMode: 'now',
    });

    // createAuthorization lands on the authorizations list; the new Records
    // authority should now be listed.
    await expect(page.getByText('Records').first()).toBeVisible({ timeout: 10_000 });
  });

  test('1.5 Gateway: create authorization with Review Each Action commit', async ({ page }) => {
    // Same reason as 1.4 - this one grants under the Records profile again, in review
    // mode. (It used the CRM before; on a production gateway the practice CRM is
    // paused, so it offers no "Give a mandate" - see 1.3.)
    await ensureProfileEnabledForActiveGroups(apiKey, RECORDS_PROFILE, ALICE.id);
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);

    await createAuthorization(page, {
      profileName: 'Records',
      bounds: { write_daily_max: '5' },
      intent: 'Need records operations under review. Each action requires manual approval before executing.',
      title: 'Records: review mode',
      commitMode: 'per-action',
    });

    // createAuthorization lands on the authorizations list; the new Records
    // (review-mode) authority should now be listed.
    await expect(page.getByText('Records').first()).toBeVisible({ timeout: 10_000 });
  });

  test('1.6 Gateway: revoke authorization', async ({ page }) => {
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);

    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates**');
    await expect(page.locator('.page-title')).toHaveText('Mandates', { timeout: 10_000 });

    // Revoke is inside the opened mandate card (UI spec §18) — open it, then revoke.
    const details = page.locator('.mandate-card .ob-head').first();
    if (await details.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await details.click();
    }
    const revokeBtn = page.locator('button:has-text("Revoke")').first();
    if (await revokeBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await revokeBtn.click();
      // Confirm if a confirmation button appears.
      const confirm = page.locator('button:has-text("Revoke")').nth(1);
      if (await confirm.isVisible({ timeout: 2_000 }).catch(() => false)) await confirm.click();
      await page.waitForTimeout(1500);
    }
  });

  test('1.7 Mobile menu works', async ({ browser }) => {
    const context = await browser.newContext({
      viewport: { width: 375, height: 812 },
    });
    const page = await context.newPage();

    await signInToGateway(page, apiKey);
    await handleOnboarding(page);

    // Sidebar hidden on mobile
    await expect(page.locator('.sidebar')).not.toBeVisible();

    // Hamburger menu
    const menuBtn = page.locator('.mobile-menu-btn');
    await expect(menuBtn).toBeVisible({ timeout: 5_000 });
    await menuBtn.click();

    // Mobile menu opens
    await expect(page.locator('.mobile-menu-panel')).toBeVisible();
    await expect(page.locator('.mobile-menu-item:has-text("Dashboard")')).toBeVisible();
    await expect(page.locator('.mobile-menu-item:has-text("Approvals")')).toBeVisible();

    // Click nav item — navigates and closes
    await page.click('.mobile-menu-item:has-text("Connectors")');
    await expect(page.locator('.mobile-menu-panel')).not.toBeVisible();

    await page.close();
  });
});
