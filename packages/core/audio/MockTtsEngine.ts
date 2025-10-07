import type { ITtsEngine, TtsSynthesisOptions, TtsSynthesisResult } from "./ITtsEngine";

function createBeepBuffer(durationMs: number, sampleRate = 16000): Uint8Array {
  const totalSamples = Math.floor((durationMs / 1000) * sampleRate);
  const buffer = new Uint8Array(totalSamples);
  for (let i = 0; i < totalSamples; i++) {
    buffer[i] = i % 2 === 0 ? 255 : 0;
  }
  return buffer;
}

async function* createMockStream(durationMs: number): AsyncIterable<Uint8Array> {
  const chunkDuration = 200;
  for (let elapsed = 0; elapsed < durationMs; elapsed += chunkDuration) {
    yield createBeepBuffer(chunkDuration);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

export class MockTtsEngine implements ITtsEngine {
  readonly name = "mock";

  async synthesize(
    text: string,
    voiceModelId: string,
    options?: TtsSynthesisOptions
  ): Promise<TtsSynthesisResult> {
    const speed = options?.speed ?? 1;
    const duration = Math.max(1000, Math.ceil((text.length / 10) * 1000 * (1 / speed)));

    return {
      audioStream: createMockStream(duration),
      transcriptTimestamps: text
        .split(/(?<=[.!?])\s+/)
        .filter(Boolean)
        .map((sentence, index, sentences) => {
          const step = duration / sentences.length;
          const startMs = Math.floor(step * index);
          return {
            startMs,
            endMs: Math.floor(startMs + step),
            text: sentence
          };
        })
    };
  }
}

export const createMockTtsEngine = (): ITtsEngine => new MockTtsEngine();
