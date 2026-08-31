import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { gameSymbolsPlugin } from './gameSymbolsPlugin'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    gameSymbolsPlugin(
      process.env.GSVIBE_GAMESYMBOLS_DIR
        ? fileURLToPath(new URL(process.env.GSVIBE_GAMESYMBOLS_DIR, import.meta.url))
        : fileURLToPath(new URL('./.test-gamesymbols', import.meta.url)),
    ),
  ],
  base: '/GoldSrc_VibeSignatures/',
})
