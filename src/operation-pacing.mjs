import { randomInt } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

export async function pauseBeforeOperation(stage, { sample = randomInt, wait = sleep, log = console.log } = {}) {
  const durationMs = sample(2_000, 5_001);
  log(`[step-delay] ${stage}: ${durationMs}ms`);
  await wait(durationMs);
}
