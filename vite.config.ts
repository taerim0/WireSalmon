import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { attachCapture } from './server/capture.mjs';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'wiresalmon-capture',
      configureServer(server) {
        attachCapture(server.httpServer, server.middlewares);
      },
      configurePreviewServer(server) {
        attachCapture(server.httpServer, server.middlewares);
      },
    },
  ],
  server: { port: 5173 },
});
