export interface TtsSynthesisOptions {
  speed?: number;
  format?: "audio/wav" | "audio/mp3";
}

export interface TtsSynthesisResult {
  audioStream: AsyncIterable<Uint8Array>;
  transcriptTimestamps: Array<{
    startMs: number;
    endMs: number;
    text: string;
  }>;
}

export interface ITtsEngine {
  readonly name: string;
  synthesize(
    text: string,
    voiceModelId: string,
    options?: TtsSynthesisOptions
  ): Promise<TtsSynthesisResult>;
}

export type TtsEngineFactory = () => ITtsEngine;
