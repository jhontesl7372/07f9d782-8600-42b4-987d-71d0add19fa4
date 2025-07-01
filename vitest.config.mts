/// <reference types="vitest/config" />
import { defineConfig } from "vite"
import { configDefaults } from "vitest/config"

export default defineConfig({
  test: {
    environment: 'node',
    exclude: [...configDefaults.exclude, "e2e/*", "examples/*"],
    coverage: {
      include: ["src/**/*"],
    },
  },
})
