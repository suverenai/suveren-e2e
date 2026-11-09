/**
 * The Authority Server stops answering (frozen with SIGSTOP: it accepts connections and never replies — what a lost
 * answer looks like). The page must say so, keep trying and recover by itself, without a reload: a reload means
 * signing in again. And the gateway itself must give up on the hung call instead of waiting forever.
 */
import { execSync } from 'node:child_process';
import { test, expect, registerOnSP, signInToGateway, handleOnboarding } from './fixtures';

test('a frozen Authority Server: told what is going on, recovers without a reload or a new sign-in', async ({ page }) => {
  test.setTimeout(180_000);
  const apiKey = await registerOnSP(page, 'Frozen AS');
  await signInToGateway(page, apiKey);
  await handleOnboarding(page);
  await page.click('.sidebar-item:has-text("Mandates")');
  await expect(page.getByText('Loading...')).toHaveCount(0, { timeout: 30_000 });
  await page.click('.sidebar-item:has-text("Dashboard")');
  // Not reloaded = this marker survives to the end.
  await page.evaluate(() => { (window as unknown as { __noReload: boolean }).__noReload = true; });

  const pid = process.env.HAP_E2E_PW_AS_PID;
  expect(pid, 'the shared stack records the Authority Server process').toBeTruthy();
  execSync(`kill -STOP ${pid}`);
  try {
    await page.click('.sidebar-item:has-text("Mandates")');
    await expect(page.getByText('Loading...')).toBeVisible();

    // Two tries of 15 seconds, then the person is told.
    const notice = page.getByTestId('connection-notice');
    await expect(notice).toContainText('Could not reach the server', { timeout: 45_000 });
    await expect(notice).toContainText(/Trying again in \d+ seconds?\./);
    await expect(notice).toContainText('No need to reload');

    // The gateway's own limit: 504 instead of waiting forever.
    const started = Date.now();
    const res = await page.request.get(`${new URL(page.url()).origin}/api/mandates/mine`, { headers: { 'X-API-Key': apiKey }, timeout: 60_000 });
    expect(res.status()).toBe(504);
    expect(Date.now() - started).toBeLessThan(40_000);
  } finally {
    execSync(`kill -CONT ${pid}`);
  }

  await expect(page.getByTestId('connection-notice')).toHaveCount(0, { timeout: 60_000 });
  await expect(page.getByText('Loading...')).toHaveCount(0, { timeout: 15_000 });
  await expect(page.locator('.page-title', { hasText: 'Mandates' })).toBeVisible();
  expect(page.url()).not.toContain('/login');
  expect(await page.evaluate(() => (window as unknown as { __noReload?: boolean }).__noReload)).toBe(true);
});
