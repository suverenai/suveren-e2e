import { stopServers } from './fixtures';
import { finishRun } from '../src/helpers/process-registry';

export default async function globalTeardown() {
  await stopServers();
  // Warns (with pids) and kills if anything this run started is still alive.
  await finishRun();
}
