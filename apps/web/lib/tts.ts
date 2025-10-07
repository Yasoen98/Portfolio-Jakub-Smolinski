import { createExternalTtsEngine, createMockTtsEngine, ITtsEngine } from "@voxbook/core";

let engine: ITtsEngine | null = null;

export function getTtsEngine(): ITtsEngine {
  if (engine) return engine;
  if (process.env.FEATURE_EXTERNAL_TTS === "true") {
    engine = createExternalTtsEngine();
  } else {
    engine = createMockTtsEngine();
  }
  return engine;
}
