import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { attachCapture } from './server/capture.mjs';

// 빌드한 사이트가 다른 서버로 아무것도 보내지 못하게 브라우저에 지시한다.
// 코드가 바뀌더라도 캡처 내용이 밖으로 나가는 요청은 브라우저가 막는다.
// 개발 서버는 인라인 스크립트(HMR)를 쓰기 때문에 빌드 결과에만 넣는다.
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'wiresalmon-csp',
      apply: 'build',
      transformIndexHtml: () => [{ tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: CONTENT_SECURITY_POLICY }, injectTo: 'head-prepend' }],
    },
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
