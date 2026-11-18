import { existsSync } from 'node:fs';
import { join } from 'node:path';

/**
 * A gateway UI source file, for the "does this gateway have feature X" checks.
 * The approval card and its helpers moved from apps/ui/src to
 * packages/approval-card/src (device-keys plan step 9), so a check that looks
 * only in apps/ui would silently skip its test. Returns the apps/ui path when
 * it exists, else the package path when that exists, else the apps/ui path.
 */
export function gwUiFile(gwDir: string, ...parts: string[]): string {
  const ui = join(gwDir, 'apps', 'ui', 'src', ...parts);
  if (existsSync(ui)) return ui;
  const card = join(gwDir, 'packages', 'approval-card', 'src', ...parts);
  return existsSync(card) ? card : ui;
}
