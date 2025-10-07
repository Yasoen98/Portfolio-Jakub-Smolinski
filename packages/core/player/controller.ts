export interface PlaybackChunk {
  documentId: string;
  order: number;
  text: string;
}

export interface PlaybackSource {
  fetchChunk(order: number): Promise<PlaybackChunk | null>;
  prefetchChunk(order: number): Promise<void>;
}

export interface PlaybackEvents {
  onChunk?(chunk: PlaybackChunk): void;
  onPrefetch?(order: number): void;
  onEnd?(): void;
}

export interface PlaybackControllerOptions {
  prefetchDepth?: number;
}

export class PlaybackController {
  private currentOrder: number;
  private playing = false;
  private readonly options: Required<PlaybackControllerOptions>;

  constructor(
    private readonly source: PlaybackSource,
    private readonly events: PlaybackEvents = {},
    options: PlaybackControllerOptions = {}
  ) {
    this.options = {
      prefetchDepth: options.prefetchDepth ?? 2
    };
    this.currentOrder = 0;
  }

  async start(order = 0) {
    this.playing = true;
    this.currentOrder = order;
    await this.playCurrent();
  }

  stop() {
    this.playing = false;
  }

  async seek(order: number) {
    this.currentOrder = order;
    if (this.playing) {
      await this.playCurrent();
    }
  }

  private async playCurrent() {
    if (!this.playing) return;
    const chunk = await this.source.fetchChunk(this.currentOrder);
    if (!chunk) {
      this.events.onEnd?.();
      return;
    }

    this.events.onChunk?.(chunk);

    for (let depth = 1; depth <= this.options.prefetchDepth; depth += 1) {
      const targetOrder = this.currentOrder + depth;
      await this.source.prefetchChunk(targetOrder);
      this.events.onPrefetch?.(targetOrder);
    }
  }

  async next() {
    this.currentOrder += 1;
    await this.playCurrent();
  }
}

export const createPlaybackController = (
  source: PlaybackSource,
  events?: PlaybackEvents,
  options?: PlaybackControllerOptions
) => new PlaybackController(source, events, options);
