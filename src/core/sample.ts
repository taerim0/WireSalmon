// 학습용 샘플 캡처를 코드로 만들어 낸다. 실제 캡처 파일과 똑같은 pcap 바이트가 나온다.

type Bytes = Uint8Array | number[];

function cat(...parts: Bytes[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let o = 0;
  for (const part of parts) {
    out.set(part, o);
    o += part.length;
  }
  return out;
}

const be16 = (n: number) => [(n >> 8) & 255, n & 255];
const be32 = (n: number) => [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
const macBytes = (s: string) => s.split(':').map((x) => parseInt(x, 16));
const ipBytes = (s: string) => s.split('.').map(Number);
const str = (s: string) => Array.from(new TextEncoder().encode(s));

const PC = { mac: '3c:22:fb:11:22:33', ip: '192.168.0.10' };
const GW = { mac: '00:1a:2b:aa:bb:01', ip: '192.168.0.1' };
const BROADCAST = 'ff:ff:ff:ff:ff:ff';
const WEB_IP = '93.184.216.34';
const SECURE_IP = '203.0.113.7';
const DNS_IP = '8.8.8.8';

let ipId = 1;
const eth = (dst: string, src: string, type: number, payload: Bytes) => cat(macBytes(dst), macBytes(src), be16(type), payload);
const ip4 = (src: string, dst: string, proto: number, payload: Bytes, ttl = 64) =>
  cat([0x45, 0, ...be16(20 + payload.length), ...be16(ipId++), 0x40, 0, ttl, proto, 0, 0, ...ipBytes(src), ...ipBytes(dst)], payload);
const udp = (sp: number, dp: number, payload: Bytes) => cat([...be16(sp), ...be16(dp), ...be16(8 + payload.length), 0, 0], payload);
const tcp = (sp: number, dp: number, seq: number, ack: number, flags: number, payload: Bytes = []) =>
  cat([...be16(sp), ...be16(dp), ...be32(seq), ...be32(ack), 0x50, flags, ...be16(64240), 0, 0, 0, 0], payload);

const SYN = 0x02;
const ACK = 0x10;
const PSH = 0x08;
const FIN = 0x01;

const out = (proto: number, dstIp: string, payload: Bytes) => eth(GW.mac, PC.mac, 0x0800, ip4(PC.ip, dstIp, proto, payload));
const inn = (proto: number, srcIp: string, payload: Bytes, ttl = 56) => eth(PC.mac, GW.mac, 0x0800, ip4(srcIp, PC.ip, proto, payload, ttl));

const arp = (op: number, sha: string, spa: string, tha: string, tpa: string) => [0, 1, 8, 0, 6, 4, 0, op, ...macBytes(sha), ...ipBytes(spa), ...macBytes(tha), ...ipBytes(tpa)];

const qname = (name: string) => [...name.split('.').flatMap((label) => [label.length, ...str(label)]), 0];
const dnsQuery = (id: number, name: string) => [...be16(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...qname(name), 0, 1, 0, 1];
const dnsAnswer = (id: number, name: string, ip: string) => [
  ...be16(id), 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, ...qname(name), 0, 1, 0, 1,
  0xc0, 0x0c, 0, 1, 0, 1, ...be32(300), 0, 4, ...ipBytes(ip),
];

function dhcp(op: number, type: number, yourIp: string, options: number[] = []): Uint8Array {
  const b = new Uint8Array(240);
  b.set([op, 1, 6, 0, ...be32(0x3903f326)]);
  b.set(ipBytes(yourIp), 16);
  b.set(macBytes(PC.mac), 28);
  b.set([99, 130, 83, 99], 236);
  return cat(b, [53, 1, type, ...options, 255]);
}

const filler = (n: number, seed: number) => Array.from({ length: n }, (_, i) => (i * 37 + seed * 101 + 13) & 255);

function clientHello(host: string): number[] {
  const name = str(host);
  const ext = [0, 0, ...be16(name.length + 5), ...be16(name.length + 3), 0, ...be16(name.length), ...name];
  const body = [3, 3, ...filler(32, 1), 0, 0, 2, 0x13, 0x01, 1, 0, ...be16(ext.length), ...ext];
  const handshake = [1, 0, ...be16(body.length), ...body];
  return [22, 3, 1, ...be16(handshake.length), ...handshake];
}

function serverHello(): number[] {
  const body = [3, 3, ...filler(32, 2), 0, 0x13, 0x01, 0, 0, 0];
  const handshake = [2, 0, ...be16(body.length), ...body];
  return [22, 3, 3, ...be16(handshake.length), ...handshake];
}

const appData = (n: number, seed: number) => [23, 3, 3, ...be16(n), ...filler(n, seed)];

/** [시간 간격(ms), 프레임] 목록을 pcap 파일 바이트로 만든다 */
function toPcap(frames: [number, Uint8Array][]): Uint8Array {
  const parts: Bytes[] = [[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, ...le32(0), ...le32(0), ...le32(65535), ...le32(1)]];
  let micros = 0;
  for (const [gapMs, frame] of frames) {
    micros += gapMs * 1000;
    parts.push([...le32(1760000000 + Math.floor(micros / 1e6)), ...le32(micros % 1e6), ...le32(frame.length), ...le32(frame.length)], frame);
  }
  return cat(...parts);
}

/** TCP 연결 맺기 3단계 */
function handshake(port: number, serverIp: string, dp: number, c: number, s: number): [number, Uint8Array][] {
  return [
    [30, out(6, serverIp, tcp(port, dp, c, 0, SYN))],
    [18, inn(6, serverIp, tcp(dp, port, s, c + 1, SYN | ACK))],
    [1, out(6, serverIp, tcp(port, dp, c + 1, s + 1, ACK))],
  ];
}

/** 와이파이에 접속해서 웹사이트 두 곳을 열어 보는 상황. bodyLine은 웹 페이지 본문에 들어갈 한 문장. */
export function buildWebVisitSample(bodyLine: string): Uint8Array {
  ipId = 1;
  const frames: [number, Uint8Array][] = [];
  const bcast = (sp: number, dp: number, src: string, payload: Bytes, srcMac = PC.mac) =>
    eth(BROADCAST, srcMac, 0x0800, ip4(src, '255.255.255.255', 17, udp(sp, dp, payload)));

  // 1. IP 주소 받기
  const lease = [1, 4, 255, 255, 255, 0, 3, 4, ...ipBytes(GW.ip), 6, 4, ...ipBytes(DNS_IP), 51, 4, ...be32(86400)];
  frames.push([0, bcast(68, 67, '0.0.0.0', dhcp(1, 1, '0.0.0.0', [12, 5, ...str('my-pc')]))]);
  frames.push([12, bcast(67, 68, GW.ip, dhcp(2, 2, PC.ip, lease), GW.mac)]);
  frames.push([3, bcast(68, 67, '0.0.0.0', dhcp(1, 3, '0.0.0.0', [50, 4, ...ipBytes(PC.ip)]))]);
  frames.push([9, bcast(67, 68, GW.ip, dhcp(2, 5, PC.ip, lease), GW.mac)]);

  // 2. 공유기의 MAC 주소 알아내기
  frames.push([150, eth(BROADCAST, PC.mac, 0x0806, arp(1, PC.mac, PC.ip, '00:00:00:00:00:00', GW.ip))]);
  frames.push([2, eth(PC.mac, GW.mac, 0x0806, arp(2, GW.mac, GW.ip, PC.mac, PC.ip))]);

  // 3. example.com 접속: 이름 찾기 → 연결 → 요청 → 응답 → 종료
  frames.push([400, out(17, DNS_IP, udp(53124, 53, dnsQuery(0x1a2b, 'example.com')))]);
  frames.push([24, inn(17, DNS_IP, udp(53, 53124, dnsAnswer(0x1a2b, 'example.com', WEB_IP)), 117)]);

  const request = str('GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: WireSalmon-Browser/1.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n');
  const html = `<!doctype html>\n<html><head><title>Example Domain</title></head>\n<body><h1>Example Domain</h1><p>${bodyLine}</p></body></html>\n`;
  // 실제 서버가 흔히 그러듯 응답의 헤더와 본문을 서로 다른 패킷에 나눠 보낸다
  const responseHead = str(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: ${str(html).length}\r\nServer: ExampleServer\r\n\r\n`);
  const responseBody = str(html);
  let c = 1000;
  let s = 5000;
  frames.push(...handshake(51000, WEB_IP, 80, c, s));
  c++;
  s++;
  frames.push([2, out(6, WEB_IP, tcp(51000, 80, c, s, PSH | ACK, request))]);
  c += request.length;
  frames.push([19, inn(6, WEB_IP, tcp(80, 51000, s, c, ACK))]);
  frames.push([6, inn(6, WEB_IP, tcp(80, 51000, s, c, ACK, responseHead))]);
  s += responseHead.length;
  frames.push([1, inn(6, WEB_IP, tcp(80, 51000, s, c, PSH | ACK, responseBody))]);
  s += responseBody.length;
  frames.push([1, out(6, WEB_IP, tcp(51000, 80, c, s, ACK))]);
  frames.push([4, inn(6, WEB_IP, tcp(80, 51000, s, c, FIN | ACK))]);
  frames.push([1, out(6, WEB_IP, tcp(51000, 80, c, s + 1, FIN | ACK))]);
  frames.push([18, inn(6, WEB_IP, tcp(80, 51000, s + 1, c + 1, ACK))]);

  // 4. 암호화된 사이트 접속
  frames.push([900, out(17, DNS_IP, udp(53990, 53, dnsQuery(0x7c01, 'secure.example.com')))]);
  frames.push([21, inn(17, DNS_IP, udp(53, 53990, dnsAnswer(0x7c01, 'secure.example.com', SECURE_IP)), 117)]);
  c = 2000;
  s = 9000;
  frames.push(...handshake(51001, SECURE_IP, 443, c, s));
  c++;
  s++;
  const tlsSteps: [boolean, number[]][] = [
    [true, clientHello('secure.example.com')],
    [false, serverHello()],
    [false, [20, 3, 3, 0, 1, 1, ...appData(220, 3)]],
    [true, [20, 3, 3, 0, 1, 1, ...appData(64, 4)]],
    [true, appData(180, 5)],
    [false, appData(1200, 6)],
    [false, appData(840, 7)],
  ];
  for (const [fromClient, payload] of tlsSteps) {
    if (fromClient) {
      frames.push([8, out(6, SECURE_IP, tcp(51001, 443, c, s, PSH | ACK, payload))]);
      c += payload.length;
      frames.push([17, inn(6, SECURE_IP, tcp(443, 51001, s, c, ACK))]);
    } else {
      frames.push([5, inn(6, SECURE_IP, tcp(443, 51001, s, c, PSH | ACK, payload))]);
      s += payload.length;
      frames.push([1, out(6, SECURE_IP, tcp(51001, 443, c, s, ACK))]);
    }
  }

  // 5. 핑
  for (let seq = 1; seq <= 2; seq++) {
    const body = [...be16(1), ...be16(seq), ...str('abcdefghijklmnopqrstuvwabcdefghi')];
    frames.push([seq === 1 ? 1200 : 980, out(1, DNS_IP, [8, 0, 0, 0, ...body])]);
    frames.push([23, inn(1, DNS_IP, [0, 0, 0, 0, ...body], 117)]);
  }

  return toPcap(frames);
}

const RST = 0x04;

const dnsNoSuchName = (id: number, name: string) => [...be16(id), 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0, ...qname(name), 0, 1, 0, 1];

/** 요청 하나에 응답 하나가 오는 HTTP 대화. waitMs는 서버가 답을 시작하기까지 걸리는 시간. */
function httpExchange(port: number, ip: string, host: string, path: string, waitMs: number, statusLine: string, body: string): [number, Uint8Array][] {
  const request = str(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: WireSalmon-Browser/1.0\r\nConnection: close\r\n\r\n`);
  const response = str(`HTTP/1.1 ${statusLine}\r\nContent-Type: text/plain\r\nContent-Length: ${str(body).length}\r\n\r\n${body}`);
  let c = port * 7;
  let s = port * 13;
  const frames = handshake(port, ip, 80, c, s);
  c++;
  s++;
  frames.push([2, out(6, ip, tcp(port, 80, c, s, PSH | ACK, request))]);
  c += request.length;
  frames.push([18, inn(6, ip, tcp(80, port, s, c, ACK))]);
  frames.push([Math.max(waitMs - 18, 1), inn(6, ip, tcp(80, port, s, c, PSH | ACK, response))]);
  s += response.length;
  frames.push([1, out(6, ip, tcp(port, 80, c, s, ACK))]);
  frames.push([3, inn(6, ip, tcp(80, port, s, c, FIN | ACK))]);
  frames.push([1, out(6, ip, tcp(port, 80, c, s + 1, FIN | ACK))]);
  frames.push([18, inn(6, ip, tcp(80, port, s + 1, c + 1, ACK))]);
  return frames;
}

/** 여러 가지가 잘 안 되는 상황을 모은 캡처: 진단과 시간 분해를 연습하기 위한 것 */
export function buildTroubleSample(): Uint8Array {
  ipId = 1;
  const frames: [number, Uint8Array][] = [];

  // 1. 주소 오타: 없는 이름
  frames.push([0, out(17, DNS_IP, udp(50111, 53, dnsQuery(0x0101, 'wwww.example.com')))]);
  frames.push([26, inn(17, DNS_IP, udp(53, 50111, dnsNoSuchName(0x0101, 'wwww.example.com')), 117)]);

  // 2. 서버 프로그램이 꺼져 있음: 연결 거부
  frames.push([300, out(6, '203.0.113.20', tcp(52001, 8080, 7000, 0, SYN))]);
  frames.push([22, inn(6, '203.0.113.20', tcp(8080, 52001, 0, 7001, RST | ACK))]);

  // 3. 방화벽이 조용히 버림: 아무 답도 없음
  for (const gap of [400, 1000, 2000]) frames.push([gap, out(6, '198.51.100.9', tcp(52002, 22, 8000, 0, SYN))]);

  // 4. 답 없는 핑
  for (let seq = 1; seq <= 3; seq++) frames.push([seq === 1 ? 200 : 1000, out(1, '10.255.255.1', [8, 0, 0, 0, ...be16(2), ...be16(seq), ...str('abcdefghijklmnopqrstuvwabcdefghi')])]);

  // 5. 같은 네트워크에 없는 장비 찾기
  for (let i = 0; i < 3; i++) frames.push([i === 0 ? 150 : 1000, eth(BROADCAST, PC.mac, 0x0806, arp(1, PC.mac, PC.ip, '00:00:00:00:00:00', '192.168.0.77'))]);

  // 6. 답하지 않는 DNS 서버
  for (const gap of [200, 1000]) frames.push([gap, out(17, '9.9.9.9', udp(50222, 53, dnsQuery(0x0202, 'example.org')))]);

  // 7. 느린 DNS와 느린 서버
  frames.push([500, out(17, DNS_IP, udp(50333, 53, dnsQuery(0x0303, 'slow.example.com')))]);
  frames.push([180, inn(17, DNS_IP, udp(53, 50333, dnsAnswer(0x0303, 'slow.example.com', '203.0.113.80')), 117)]);
  frames.push(...httpExchange(52003, '203.0.113.80', 'slow.example.com', '/report', 1850, '200 OK', 'report ready\n'));

  // 8. 서버 오류
  frames.push([300, out(17, DNS_IP, udp(50444, 53, dnsQuery(0x0404, 'shop.example.com')))]);
  frames.push([20, inn(17, DNS_IP, udp(53, 50444, dnsAnswer(0x0404, 'shop.example.com', '203.0.113.81')), 117)]);
  frames.push(...httpExchange(52004, '203.0.113.81', 'shop.example.com', '/cart/checkout', 40, '500 Internal Server Error', 'something went wrong\n'));

  // 9. 없는 페이지
  frames.push(...httpExchange(52005, WEB_IP, 'example.com', '/old-page', 25, '404 Not Found', 'no such page\n').map(([gap, frame], i): [number, Uint8Array] => [i === 0 ? 200 : gap, frame]));

  // 10. 패킷이 사라지다가 끝내 끊기는 연결
  const lossy = '203.0.113.90';
  frames.push(...handshake(52006, lossy, 5000, 9000, 4000).map(([gap, frame], i): [number, Uint8Array] => [i === 0 ? 300 : gap, frame]));
  const chunk = filler(300, 9);
  for (const gap of [5, 300, 600]) frames.push([gap, out(6, lossy, tcp(52006, 5000, 9001, 4001, PSH | ACK, chunk))]);
  frames.push([40, inn(6, lossy, tcp(5000, 52006, 4001, 9301, ACK))]);
  frames.push([12, inn(6, lossy, tcp(5000, 52006, 4001, 9301, PSH | ACK, filler(500, 10)))]);
  frames.push([1, out(6, lossy, tcp(52006, 5000, 9301, 4501, ACK))]);
  frames.push([900, inn(6, lossy, tcp(5000, 52006, 4501, 9301, RST | ACK))]);

  return toPcap(frames);
}

/** 내장 샘플 목록. 제목과 설명은 언어별 사전(samples)에 같은 id로 들어 있다. */
export const SAMPLES: { id: string; build: (bodyLine: string) => Uint8Array }[] = [
  { id: 'web-visit', build: buildWebVisitSample },
  { id: 'trouble', build: buildTroubleSample },
];
