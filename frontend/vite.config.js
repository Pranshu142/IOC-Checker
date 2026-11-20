import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Local dev: /api is proxied to the Java server, so VITE_API_URL can stay empty.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  optimizeDeps: { include: ['exceljs'] },
  server: { proxy: { '/api': 'http://localhost:8080' } },
});
