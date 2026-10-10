// 실시간 캡처 헬퍼: dumpcap(Wireshark에 포함)을 실행해 캡처 스트림을 WebSocket으로 브라우저에 전달한다.
// 브라우저는 네트워크 카드에 직접 접근할 수 없어서 이 로컬 프로세스가 대신 캡처한다.
import { spawn, execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import os from 'node:os';
import { WebSocketServer } from 'ws';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const HIGH_WATER = 4 * 1024 * 1024;

function findDumpcap() {
  const candidates =
    process.platform === 'win32'
      ? ['C:\\Program Files\\Wireshark\\dumpcap.exe', 'C:\\Program Files (x86)\\Wireshark\\dumpcap.exe']
      : ['/usr/bin/dumpcap', '/usr/local/bin/dumpcap', '/opt/homebrew/bin/dumpcap', '/Applications/Wireshark.app/Contents/MacOS/dumpcap'];
  return [process.env.WIRESALMON_DUMPCAP, ...candidates].find((c) => c && existsSync(c)) ?? 'dumpcap';
}

function listInterfaces() {
  return new Promise((resolve, reject) => {
    execFile(findDumpcap(), ['-D'], { encoding: 'utf8', windowsHide: true }, (err, stdout, stderr) => {
      if (err && !stdout && !stderr) return reject(err);
      const local = os.networkInterfaces();
      const list = [];
      for (const line of `${stdout}\n${stderr}`.split(/\r?\n/)) {
        const m = /^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$/.exec(line);
        if (!m) continue;
        const name = m[3] ?? m[2];
        const addrs = local[name] ?? local[m[2]] ?? [];
        const v4 = addrs.find((a) => a.family === 'IPv4' && !a.internal);
        list.push({ id: m[1], name, address: v4?.address ?? null });
      }
      list.sort((a, b) => Number(!!b.address) - Number(!!a.address));
      resolve(list);
    });
  });
}

// 다른 웹사이트가 localhost의 캡처 소켓에 몰래 붙는 것을 막는다.
function isSameLocalOrigin(req) {
  const host = req.headers.host ?? '';
  const origin = req.headers.origin;
  if (!origin) return false;
  try {
    const o = new URL(origin);
    return o.host === host && LOCAL_HOSTS.has(o.hostname);
  } catch {
    return false;
  }
}

export function attachCapture(httpServer, middlewares) {
  if (!httpServer) return;

  middlewares.use('/api/interfaces', (_req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    listInterfaces().then(
      (interfaces) => res.end(JSON.stringify({ interfaces })),
      () => {
        res.statusCode = 503;
        res.end(JSON.stringify({ error: 'dumpcap을 찾지 못했습니다. Wireshark(Npcap 포함)를 설치해 주세요.' }));
      },
    );
  });

  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== '/capture') return;
    const iface = url.searchParams.get('iface') ?? '';
    if (!isSameLocalOrigin(req) || !/^\d+$/.test(iface)) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => startCapture(ws, iface));
  });
}

function startCapture(ws, iface) {
  const child = spawn(findDumpcap(), ['-i', iface, '-w', '-', '-q'], { windowsHide: true });
  let stderr = '';

  child.stdout.on('data', (chunk) => {
    if (ws.readyState !== ws.OPEN) return;
    ws.send(chunk, { binary: true });
    if (ws.bufferedAmount > HIGH_WATER) {
      child.stdout.pause();
      const timer = setInterval(() => {
        if (ws.bufferedAmount < HIGH_WATER / 2 || ws.readyState !== ws.OPEN) {
          clearInterval(timer);
          child.stdout.resume();
        }
      }, 50);
    }
  });
  child.stderr.on('data', (chunk) => {
    stderr = (stderr + chunk).slice(-2000);
  });
  child.on('error', () => {
    if (ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify({ error: 'dumpcap을 실행하지 못했습니다. Wireshark(Npcap 포함)가 설치되어 있는지 확인해 주세요.' }));
      ws.close();
    }
  });
  child.on('exit', (code) => {
    if (ws.readyState === ws.OPEN) {
      if (code) ws.send(JSON.stringify({ error: `캡처가 중단되었습니다. ${stderr.trim().split(/\r?\n/).pop() ?? ''}` }));
      ws.close();
    }
  });
  ws.on('close', () => child.kill());
  ws.on('error', () => child.kill());
}
