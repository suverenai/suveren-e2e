import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The give page's Title field, found by its label "Title" (apps/ui/src/pages/AgentReviewPage.tsx:
 * `.field-editable` > `.field-label` "✎ Title" + the input). Never by placeholder or input order.
 */
export function titleField(page: Page): Locator {
  return page.locator('.field-editable')
    .filter({ has: page.locator('.field-label', { hasText: /^\W*Title$/ }) })
    .locator('input');
}

/** Types the title like a person and checks it is still there a moment later (the default title must not replace it). */
export async function typeTitle(page: Page, title: string): Promise<void> {
  const field = titleField(page);
  await expect(field).toHaveCount(1, { timeout: 30_000 });
  await field.fill(title);
  await page.waitForTimeout(1_500);
  await expect(field, 'the typed title stays (the default title must never overwrite it)').toHaveValue(title);
}
