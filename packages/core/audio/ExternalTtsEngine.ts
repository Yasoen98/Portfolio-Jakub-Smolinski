import type { ITtsEngine, TtsSynthesisOptions, TtsSynthesisResult } from "./ITtsEngine";

export class ExternalTtsEngine implements ITtsEngine {
  readonly name = "external";

  async synthesize(
    text: string,
    voiceModelId: string,
    options?: TtsSynthesisOptions
  ): Promise<TtsSynthesisResult> {
    if (!process.env.EXTERNAL_TTS_API_URL) {
      throw new Error("External TTS provider is not configured");
    }

    const response = await fetch(process.env.EXTERNAL_TTS_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.EXTERNAL_TTS_API_KEY ?? ""}`
      },
      body: JSON.stringify({ text, voiceModelId, options })
    });

    if (!response.body) {
      throw new Error("External TTS API did not return a stream");
    }

    const transcriptHeader = response.headers.get("x-transcript") ?? "[]";
    const transcriptTimestamps = JSON.parse(transcriptHeader) as TtsSynthesisResult["transcriptTimestamps"];

    async function* streamFromReadable(): AsyncIterable<Uint8Array> {
      const reader = response.body!.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            yield value;
          }
        }
      } finally {
        reader.releaseLock();
      }
    }

    return {
      audioStream: streamFromReadable(),
      transcriptTimestamps
    };
  }
}

export const createExternalTtsEngine = (): ITtsEngine => new ExternalTtsEngine();
