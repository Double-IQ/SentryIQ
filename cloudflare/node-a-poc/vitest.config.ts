import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: [
      { find: /^fs$/, replacement: fileURLToPath(new URL("./src/tuf-fs.ts", import.meta.url)) },
      { find: "fs/promises", replacement: fileURLToPath(new URL("./src/tuf-fs-promises.ts", import.meta.url)) }
    ]
  },
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.jsonc"
      }
    })
  ]
});
