import { defineConfig } from "vitest/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    setupFiles: [path.resolve(__dirname, "tests/setup.ts")]
  },
  resolve: {
    alias: {
      "@voxbook/core": path.resolve(__dirname, "../../packages/core/index.ts")
    }
  }
});
