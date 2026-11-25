/**
 * The Authority Server's dashboard, opened while signed out, sends the browser to the login page.
 *
 * Why this exists: the middleware's sign-in redirect became a relative Location ('/login'), and Next 14.2's middleware
 * wrapper parses every middleware Location with `new NextURL(location)` and no base. It threw "Invalid URL", so anyone
 * signed out who opened a /dashboard link got a 500 — with the device-keys switch on or off. The unit test called
 * middleware() directly and passed; nothing opened /dashboard signed out on a real `next start` AS. This does, in both
 * switch settings (the spec runs in both full-suite jobs).
 */
import { test, expect, SP_URL } from './fixtures';

test.describe('the AS dashboard, signed out', () => {
  for (const path of ['/dashboard', '/dashboard/mandates']) {
    test(`${path} redirects to /login (never a 500)`, async ({ request, browser }) => {
      // The raw answer: a redirect to the login page, not a server error.
      const raw = await request.get(`${SP_URL}${path}`, { maxRedirects: 0 });
      expect(raw.status(), `GET ${path} signed out`).toBe(307);
      const loc = raw.headers()['location'] ?? '';
      expect(new URL(loc, SP_URL).pathname).toBe('/login');

      // In a browser with no session cookie: the login page renders.
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        const res = await page.goto(`${SP_URL}${path}`);
        expect(res?.status(), 'the page the browser lands on').toBe(200);
        expect(new URL(page.url()).pathname).toBe('/login');
      } finally {
        await context.close();
      }
    });
  }
});
