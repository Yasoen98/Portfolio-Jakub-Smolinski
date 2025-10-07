import { describe, expect, it } from "vitest";
import { createPlaybackController, type PlaybackChunk } from "@voxbook/core";

describe("PlaybackController", () => {
  it("prefetches kolejne chunk", async () => {
    const fetched: number[] = [];
    const prefetched: number[] = [];

    const source = {
      async fetchChunk(order: number): Promise<PlaybackChunk | null> {
        fetched.push(order);
        if (order > 2) return null;
        return { documentId: "doc", order, text: `chunk-${order}` };
      },
      async prefetchChunk(order: number) {
        prefetched.push(order);
      }
    };

    const controller = createPlaybackController(source, undefined, { prefetchDepth: 2 });
    await controller.start(0);
    expect(fetched).toContain(0);
    expect(prefetched).toContain(1);
  });
});
