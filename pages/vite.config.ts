import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'
import { gameSymbolsPlugin } from './gameSymbolsPlugin'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    gameSymbolsPlugin(resolve(process.env.GSVIBE_GAMESYMBOLS_DIR ?? '.test-gamesymbols')),
  ],
  base: '/GoldSrc_VibeSignatures/',
})
