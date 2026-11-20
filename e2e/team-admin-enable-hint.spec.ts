/**
 * Found by the maintainer on the device-keys dev lane (2026-11-20): on "New mandate" every area card of a team said
 * "Ask an admin of <team> to enable …" although the person WAS that admin, with no way shown to do it.
 *
 * Real Authority Server, real gateway, real browser. A fresh team whose areas are not enabled:
 *   - the admin sees "You are an admin of <team>: enable … in the team's settings" and a link to the team's area
 *     settings on the Authority Server (`/dashboard/groups/<id>?tab=profiles`), never "Ask an admin";
 *   - a member who is not an admin keeps "Ask an admin of <team> …" and gets no link.
 * Screenshots of both cards are attached to the report.
 */
import { randomUUID } from 'node:crypto';
import type { APIRequestContext, Page, TestInfo } from '@playwright/test';
import { test, expect, SP_URL, signInToGateway, handleOnboarding } from './fixtures';

interface AsUser { id: string; apiKey: string; name: string }

async function registerAsUser(request: APIRequestContext, name: string): Promise<AsUser> {
  const email = `${name.toLowerCase()}-${randomUUID()}@test.local`;
  const res = await request.post(`${SP_URL}/api/auth/register`, { data: { name, email } });
  if (!res.ok()) throw new Error(`register ${name} failed: ${res.status()} ${await res.text()}`);
  const body = await res.json() as { apiKey: string; user: { id: string } };
  return { id: body.user.id, apiKey: body.apiKey, name };
}

async function teamWithMember(request: APIRequestContext): Promise<{ admin: AsUser; member: AsUser; groupId: string; teamName: string }> {
  const admin = await registerAsUser(request, 'Admin');
  const member = await registerAsUser(request, 'Member');
  const teamName = `Enable Hint Team ${Date.now()}`;
  const created = await request.post(`${SP_URL}/api/groups`, { headers: { 'x-api-key': admin.apiKey }, data: { name: teamName } });
  if (!created.ok()) throw new Error(`create team failed: ${created.status()} ${await created.text()}`);
  const { group } = await created.json() as { group: { id: string; inviteCode: string } };
  const join = await request.post(`${SP_URL}/api/groups/join`, { headers: { 'x-api-key': member.apiKey }, data: { inviteCode: group.inviteCode } });
  if (!join.ok()) throw new Error(`join failed: ${join.status()} ${await join.text()}`);
  if (join.status() !== 200) {
    const ok = await request.post(`${SP_URL}/api/groups/${group.id}/requests/${member.id}`, { headers: { 'x-api-key': admin.apiKey }, data: { action: 'confirm' } });
    if (!ok.ok()) throw new Error(`confirm join failed: ${ok.status()} ${await ok.text()}`);
  }
  return { admin, member, groupId: group.id, teamName };
}

async function openPicker(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle');
  await page.click('.sidebar-item:has-text("Mandates")');
  await page.waitForURL('**/mandates**');
  await page.click('button:has-text("New mandate")');
  await page.waitForSelector('.profile-grid', { timeout: 10_000 });
}

async function shot(page: Page, testInfo: TestInfo, name: string): Promise<void> {
  await testInfo.attach(name, { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
}

test.describe('team admin: a not-enabled area says how to enable it', () => {
  test('the admin gets the enable hint and a link to the team settings; a member keeps "Ask an admin"', async ({ page, request }, testInfo) => {
    const { admin, member, groupId, teamName } = await teamWithMember(request);

    // ── the admin
    await signInToGateway(page, admin.apiKey);
    await handleOnboarding(page);
    await openPicker(page);
    const adminCard = page.locator('.card', { has: page.getByText('CRM', { exact: true }) }).first();
    await expect(adminCard.locator('button:has-text("Give a mandate")')).toBeDisabled();
    await expect(adminCard).toContainText(`You are an admin of "${teamName}": enable`);
    await expect(adminCard).not.toContainText('Ask an admin');
    const link = adminCard.getByTestId('enable-in-team-settings');
    await expect(link).toBeVisible();
    const href = await link.getAttribute('href');
    expect(href).toBe(`${SP_URL.replace(/\/$/, '')}/dashboard/groups/${encodeURIComponent(groupId)}?tab=profiles`);
    await expect(link).toHaveAttribute('target', '_blank');
    await shot(page, testInfo, 'admin-not-enabled-card');

    // ── a member who is not an admin
    await signInToGateway(page, member.apiKey);
    await handleOnboarding(page);
    await openPicker(page);
    const memberCard = page.locator('.card', { has: page.getByText('CRM', { exact: true }) }).first();
    await expect(memberCard.locator('button:has-text("Give a mandate")')).toBeDisabled();
    await expect(memberCard).toContainText(`Ask an admin of "${teamName}" to enable`);
    await expect(memberCard.getByTestId('enable-in-team-settings')).toHaveCount(0);
    await shot(page, testInfo, 'member-not-enabled-card');
  });
});
