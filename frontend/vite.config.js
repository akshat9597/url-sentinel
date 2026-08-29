import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Listen on every local interface so `localhost` works consistently on
    // macOS whether the browser resolves it as IPv4 or IPv6.
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    proxy: {
      // During local development the browser talks only to Vite. Vite then
      // forwards API requests to FastAPI, avoiding CORS and hostname issues.
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
