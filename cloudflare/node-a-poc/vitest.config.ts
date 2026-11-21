import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: [
      { find: "fs/promises", replacement: fileURLToPath(new URL("./src/tuf-fs-promises.ts", import.meta.url)) },
      { find: "fs", replacement: fileURLToPath(new URL("./src/tuf-fs.ts", import.meta.url)) }
    ]
  },
  ssr: {
    noExternal: ["@sigstore/tuf", "tuf-js"]
  },
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.jsonc"
      }
    })
  ]
});
