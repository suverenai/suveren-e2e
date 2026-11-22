/**
 * The result stamp (check mark, "Signed", its line) sits in the middle of the card's free area — the card from its top to
 * the pinned Close button (or to its bottom when there is none) — never at the bottom of an empty card (UI spec §17).
 * Measured on what the person sees: the union of the stamp's visible children, not the stamp box (which fills the area).
 */
import { expect, type Locator, type Page } from '@playwright/test';

export async function expectStampCentred(stamp: Locator, what: string): Promise<{ offset: number; area: number }> {
  const m = await stamp.evaluate((el) => {
    const card = el.closest('.av3-card');
    if (!card) return null;
    const c = card.getBoundingClientRect();
    const close = card.querySelector('[data-testid="give-touch-close"], .av3-foot button');
    const bottom = close ? close.closest('footer')?.getBoundingClientRect().top ?? close.getBoundingClientRect().top : c.bottom;
    const kids = Array.from(el.children).map((k) => k.getBoundingClientRect()).filter((r) => r.height > 0);
    const top = Math.min(...kids.map((r) => r.top));
    const end = Math.max(...kids.map((r) => r.bottom));
    return { areaTop: c.top, areaBottom: bottom, contentCentre: (top + end) / 2 };
  });
  expect(m, `${what}: the stamp is inside a card`).not.toBeNull();
  // Its small line ("Recorded", …) uses the body font, not the mono font (Andreas 2026-11-22).
  const line = stamp.locator('.av3-stamp-t').first();
  if (await line.count()) {
    const [lineFont, bodyFont] = await line.evaluate((el) => [getComputedStyle(el).fontFamily, getComputedStyle(document.body).fontFamily]);
    expect(lineFont, `${what}: the stamp's small line uses the body font`).toBe(bodyFont);
  }
  const area = m!.areaBottom - m!.areaTop;
  const offset = Math.abs(m!.contentCentre - (m!.areaTop + area / 2));
  expect(offset, `${what}: the stamp's centre is ${Math.round(offset)}px from the middle of the card's free area (${Math.round(area)}px)`).toBeLessThanOrEqual(area * 0.1);
  return { offset, area };
}

/** The same check at a desktop window 900px high and at phone width, each with a screenshot. */
export async function expectStampCentredAtSizes(page: Page, stamp: Locator, what: string, shot: (name: string) => Promise<void>, prefix: string): Promise<void> {
  const before = page.viewportSize();
  for (const [name, size] of [['desktop-900', { width: 1280, height: 900 }], ['phone', { width: 390, height: 844 }]] as const) {
    await page.setViewportSize(size);
    await expect(stamp).toBeVisible();
    await expectStampCentred(stamp, `${what} (${name})`);
    await shot(`${prefix}-${name}`);
  }
  if (before) await page.setViewportSize(before);
}
