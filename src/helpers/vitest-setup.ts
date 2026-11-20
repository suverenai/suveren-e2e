/**
 * Runs in every test file (vitest `setupFiles`). After the file's own hooks —
 * sequence.hooks is 'stack', so this root-level afterAll, registered first,
 * runs last — stop every server any ProcessManager of this file started, pass
 * or fail. This is what catches a stack whose boot helper threw before the
 * suite could hold on to its ProcessManager. See process-registry.ts.
 */
import { afterAll } from 'vitest';
import { ProcessManager } from './process-manager';

afterAll(async () => {
  await ProcessManager.killEverything();
}, 60_000);
