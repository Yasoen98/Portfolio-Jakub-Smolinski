import { describe, expect, it } from "vitest";
import { chunkText } from "@voxbook/core";

describe("chunkText", () => {
  it("dzieli tekst na logiczne fragmenty", () => {
    const text = "Zdanie pierwsze. Zdanie drugie jest nieco dłuższe. Trzecie zdanie.";
    const chunks = chunkText(text, 40);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks[0].text.length).toBeLessThanOrEqual(40);
    expect(chunks[0].order).toBe(0);
    expect(chunks[1].order).toBe(1);
  });
});
