import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  ssr: {
    noExternal: ["tuf-js"]
  },
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.jsonc"
      }
    })
  ]
});
