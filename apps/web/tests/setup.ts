import { vi } from "vitest";

vi.mock("pdf-parse", () => ({
  default: async () => ({ text: "", info: {}, numpages: 1 })
}));
