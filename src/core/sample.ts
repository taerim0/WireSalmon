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
/** frag를 주면 쪼개진 조각으로 만든다: 같은 id, flags에는 "뒤에 더 있음" 표시와 위치가 들어간다 */
const ip4 = (src: string, dst: string, proto: number, payload: Bytes, ttl = 64, frag?: { id: number; flags: number }) =>
  cat([0x45, 0, ...be16(20 + payload.length), ...be16(frag?.id ?? ipId++), ...(frag ? be16(frag.flags) : [0x40, 0]), ttl, proto, 0, 0, ...ipBytes(src), ...ipBytes(dst)], payload);
const udp = (sp: number, dp: number, payload: Bytes) => cat([...be16(sp), ...be16(dp), ...be16(8 + payload.length), 0, 0], payload);
const tcp = (sp: number, dp: number, seq: number, ack: number, flags: number, payload: Bytes = [], window = 64240) =>
  cat([...be16(sp), ...be16(dp), ...be32(seq), ...be32(ack), 0x50, flags, ...be16(window), 0, 0, 0, 0], payload);

const SYN = 0x02;
const ACK = 0x10;
const PSH = 0x08;
const FIN = 0x01;

type Frag = { id: number; flags: number };
const out = (proto: number, dstIp: string, payload: Bytes, ttl = 64, frag?: Frag) => eth(GW.mac, PC.mac, 0x0800, ip4(PC.ip, dstIp, proto, payload, ttl, frag));
const inn = (proto: number, srcIp: string, payload: Bytes, ttl = 56, frag?: Frag) => eth(PC.mac, GW.mac, 0x0800, ip4(srcIp, PC.ip, proto, payload, ttl, frag));

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

// ---------------------------------------------------------------------------
// 강의 주제별 작은 샘플: 하나의 캡처가 하나의 동작만 보여 준다
// ---------------------------------------------------------------------------

type Frames = [number, Uint8Array][];

/**
 * TCP 대화를 순서대로 적어 내려가는 도우미. 순서 번호와 확인 번호를 대신 계산한다.
 * client/server는 번호를 직접 정해서 보낼 때(손실, 중복 ACK 등) 쓴다.
 */
function conversation(port: number, ip: string, dp: number) {
  const frames: Frames = [];
  const talk = {
    frames,
    /** 다음에 보낼 순서 번호 */
    c: port * 7 + 1000,
    s: port * 13 + 5000,
    client(gap: number, seq: number, ack: number, flags: number, payload: Bytes = []) {
      frames.push([gap, out(6, ip, tcp(port, dp, seq, ack, flags, payload))]);
      return talk;
    },
    server(gap: number, seq: number, ack: number, flags: number, payload: Bytes = [], window?: number) {
      frames.push([gap, inn(6, ip, tcp(dp, port, seq, ack, flags, payload, window))]);
      return talk;
    },
    open(gap = 30, serverWindow?: number) {
      talk.client(gap, talk.c, 0, SYN).server(18, talk.s, talk.c + 1, SYN | ACK, [], serverWindow).client(1, talk.c + 1, talk.s + 1, ACK);
      talk.c++;
      talk.s++;
      return talk;
    },
    send(gap: number, payload: Bytes, flags = PSH | ACK) {
      talk.client(gap, talk.c, talk.s, flags, payload);
      talk.c += payload.length + (flags & FIN ? 1 : 0);
      return talk;
    },
    reply(gap: number, payload: Bytes, flags = PSH | ACK, window?: number) {
      talk.server(gap, talk.s, talk.c, flags, payload, window);
      talk.s += payload.length + (flags & FIN ? 1 : 0);
      return talk;
    },
    /** 양쪽이 차례로 닫는다 */
    close(gap = 5) {
      return talk.send(gap, [], FIN | ACK).reply(18, [], FIN | ACK).send(1, [], ACK);
    },
  };
  return talk;
}

const httpResponse = (statusLine: string, headers: string[], body: Bytes = []) => cat(str(`${statusLine}\r\n${headers.map((h) => `${h}\r\n`).join('')}\r\n`), body);
const httpRequest = (line: string, headers: string[]) => str(`${line}\r\n${headers.map((h) => `${h}\r\n`).join('')}\r\n`);

/** 응용 계층: 객체마다 연결을 새로 맺는 HTTP/1.0과, 한 연결을 계속 쓰는 HTTP/1.1 */
function buildHttpConnections(): Uint8Array {
  ipId = 1;
  const page = str('<html><body><h1>Hello</h1><img src="/logo.png"></body></html>\n');
  const logo = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...filler(56, 3)];
  const objects: [string, string, Bytes][] = [
    ['/index.html', 'text/html', page],
    ['/logo.png', 'image/png', logo],
  ];
  const frames: Frames = [];

  // HTTP/1.0 (비지속 연결): 객체 하나를 받을 때마다 연결을 맺고 끊는다
  objects.forEach(([path, type, body], i) => {
    const talk = conversation(51010 + i, '203.0.113.10', 80).open(i === 0 ? 0 : 40);
    talk.send(2, httpRequest(`GET ${path} HTTP/1.0`, ['Host: http10.example.com'])).reply(18, [], ACK);
    talk.reply(4, httpResponse('HTTP/1.0 200 OK', [`Content-Type: ${type}`, `Content-Length: ${body.length}`], body)).send(1, [], ACK);
    talk.reply(2, [], FIN | ACK).send(1, [], FIN | ACK).reply(18, [], ACK);
    frames.push(...talk.frames);
  });

  // HTTP/1.1 (지속 연결): 연결 하나로 두 객체를 차례로 받는다
  const talk = conversation(51020, '203.0.113.11', 80).open(1500);
  for (const [path, type, body] of objects) {
    talk.send(2, httpRequest(`GET ${path} HTTP/1.1`, ['Host: http11.example.com', 'Connection: keep-alive'])).reply(18, [], ACK);
    talk.reply(4, httpResponse('HTTP/1.1 200 OK', [`Content-Type: ${type}`, `Content-Length: ${body.length}`, 'Connection: keep-alive'], body)).send(1, [], ACK);
  }
  frames.push(...talk.close(800).frames);
  return toPcap(frames);
}

/** 응용 계층: 쿠키로 사용자를 기억하고, 조건부 GET으로 바뀌지 않은 내용은 다시 받지 않는다 */
function buildHttpCookieCache(): Uint8Array {
  ipId = 1;
  const body = str('<html><body><p>Your cart is empty.</p></body></html>\n');
  const modified = 'Tue, 13 Oct 2026 03:00:00 GMT';
  const talk = conversation(51030, '203.0.113.12', 80).open(0);
  talk.send(2, httpRequest('GET /cart HTTP/1.1', ['Host: shop.example.com'])).reply(18, [], ACK);
  talk
    .reply(6, httpResponse('HTTP/1.1 200 OK', ['Content-Type: text/html', `Content-Length: ${body.length}`, `Last-Modified: ${modified}`, 'Set-Cookie: session=4f2a91; Path=/'], body))
    .send(1, [], ACK);
  // 두 번째 방문: 받아 둔 쿠키를 돌려보내고, 그 뒤로 바뀌었을 때만 달라고 한다
  talk.send(2000, httpRequest('GET /cart HTTP/1.1', ['Host: shop.example.com', 'Cookie: session=4f2a91', `If-Modified-Since: ${modified}`])).reply(18, [], ACK);
  talk.reply(3, httpResponse('HTTP/1.1 304 Not Modified', [`Last-Modified: ${modified}`])).send(1, [], ACK);
  return toPcap(talk.close(500).frames);
}

const record = (owner: number[], type: number, data: number[], ttl = 300) => [...owner, ...be16(type), 0, 1, ...be32(ttl), ...be16(data.length), ...data];
/** 질문 이름을 가리키는 포인터: 같은 이름을 다시 쓰지 않는 DNS의 압축 방식 */
const SAME_NAME = [0xc0, 0x0c];
const dnsAsk = (id: number, name: string, type: number) => [...be16(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...qname(name), ...be16(type), 0, 1];
const dnsReply = (id: number, name: string, type: number, answers: number[][]) => [
  ...be16(id), 0x81, 0x80, 0, 1, ...be16(answers.length), 0, 0, 0, 0, ...qname(name), ...be16(type), 0, 1, ...answers.flat(),
];

/** 응용 계층: DNS 레코드 종류별로 질문 하나, 답 하나 */
function buildDnsRecords(): Uint8Array {
  ipId = 1;
  const lookups: [string, number, number[][]][] = [
    ['example.com', 1, [record(SAME_NAME, 1, ipBytes(WEB_IP))]],
    ['www.example.com', 1, [record(SAME_NAME, 5, qname('example.com')), record(qname('example.com'), 1, ipBytes(WEB_IP))]],
    ['ipv6.example.com', 28, [record(SAME_NAME, 28, [0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46])]],
    ['example.net', 15, [record(SAME_NAME, 15, [...be16(10), ...qname('mail.example.net')])]],
    ['example.org', 2, [record(SAME_NAME, 2, qname('ns1.example.org')), record(SAME_NAME, 2, qname('ns2.example.org'))]],
  ];
  const frames: Frames = [];
  lookups.forEach(([name, type, answers], i) => {
    frames.push([i === 0 ? 0 : 600, out(17, DNS_IP, udp(53100 + i, 53, dnsAsk(0x2000 + i, name, type)))]);
    frames.push([22, inn(17, DNS_IP, udp(53, 53100 + i, dnsReply(0x2000 + i, name, type, answers)), 117)]);
  });
  return toPcap(frames);
}

/** 전송 계층: 같은 "hello"를 UDP로 보낼 때와 TCP로 보낼 때 */
function buildUdpVsTcp(): Uint8Array {
  ipId = 1;
  const server = '203.0.113.50';
  const hello = str('hello');
  const frames: Frames = [
    [0, out(17, server, udp(50001, 9007, hello))],
    [19, inn(17, server, udp(9007, 50001, hello))],
  ];
  const talk = conversation(50002, server, 9007).open(1000);
  talk.send(2, hello).reply(18, [], ACK).reply(1, hello).send(1, [], ACK);
  frames.push(...talk.close().frames);
  return toPcap(frames);
}

/** 전송 계층: 연결을 맺는 3단계와, 양쪽이 따로 닫는 4단계 */
function buildTcpOpenClose(): Uint8Array {
  ipId = 1;
  const talk = conversation(50010, '203.0.113.51', 9000).open(0);
  talk.send(3, str('ping\n')).reply(18, [], ACK).reply(2, str('pong\n')).send(1, [], ACK);
  // 클라이언트가 먼저 "보낼 것 없음"을 알린다. 서버는 남은 것을 마저 보낸 뒤 닫는다 (반쯤 닫힌 상태).
  talk.send(500, [], FIN | ACK).reply(18, [], ACK);
  talk.reply(40, str('bye\n')).send(1, [], ACK);
  talk.reply(5, [], FIN | ACK).send(1, [], ACK);
  return toPcap(talk.frames);
}

/** 전송 계층: 답이 없어서 기다렸다 다시 보내는 경우와, 중복 ACK 3개를 받고 바로 다시 보내는 경우 */
function buildTcpRetransmit(): Uint8Array {
  ipId = 1;
  const frames: Frames = [];

  // 1. 타임아웃 재전송: 확인이 오지 않아 1초, 다시 2초를 기다렸다가 보낸다
  const slow = conversation(50020, '203.0.113.60', 9000).open(0);
  const lost = filler(200, 1);
  for (const gap of [3, 1000, 2000]) slow.client(gap, slow.c, slow.s, PSH | ACK, lost);
  slow.c += lost.length;
  slow.reply(20, [], ACK);
  frames.push(...slow.close().frames);

  // 2. 빠른 재전송: 두 번째 조각만 사라졌다. 받는 쪽은 뒤의 조각을 받을 때마다 같은 번호를 다시 요청한다.
  const fast = conversation(50021, '203.0.113.61', 9000).open(1500);
  const start = fast.c;
  for (let i = 0; i < 5; i++) fast.send(i === 0 ? 2 : 1, filler(500, 10 + i), ACK);
  fast.server(18, fast.s, start + 500, ACK);
  for (let i = 0; i < 3; i++) fast.server(1, fast.s, start + 500, ACK);
  fast.client(1, start + 500, fast.s, ACK, filler(500, 11));
  fast.server(18, fast.s, start + 2500, ACK);
  frames.push(...fast.close().frames);
  return toPcap(frames);
}

/** 전송 계층: 받는 쪽 버퍼가 차서 보내는 쪽을 멈추게 하는 흐름 제어 */
function buildTcpFlowControl(): Uint8Array {
  ipId = 1;
  const talk = conversation(50030, '203.0.113.62', 9000).open(0, 3000);
  // 받는 프로그램이 데이터를 꺼내 가지 않아서, 받을 때마다 남은 공간이 줄어든다
  for (const room of [2000, 1000, 0]) talk.send(3, filler(1000, room), ACK).reply(18, [], ACK, room);
  // 보내는 쪽은 멈추고, 공간이 생겼는지 1바이트로 찔러 본다
  for (const gap of [500, 1000]) talk.client(gap, talk.c, talk.s, ACK, [0x2a]).server(18, talk.s, talk.c, ACK, [], 0);
  // 받는 프로그램이 데이터를 꺼내 가서 공간이 다시 생겼다
  talk.server(400, talk.s, talk.c, ACK, [], 3000);
  talk.send(2, filler(1000, 7), ACK).reply(18, [], ACK, 2000);
  return toPcap(talk.close(300).frames);
}

/** 네트워크 계층: 네트워크에 접속한 기기가 IP 주소를 받는 4단계 */
function buildDhcp(): Uint8Array {
  ipId = 1;
  const broadcast = (sp: number, dp: number, src: string, payload: Bytes, srcMac: string) => eth(BROADCAST, srcMac, 0x0800, ip4(src, '255.255.255.255', 17, udp(sp, dp, payload)));
  const lease = [1, 4, 255, 255, 255, 0, 3, 4, ...ipBytes(GW.ip), 6, 4, ...ipBytes(DNS_IP), 51, 4, ...be32(86400)];
  return toPcap([
    [0, broadcast(68, 67, '0.0.0.0', dhcp(1, 1, '0.0.0.0', [12, 5, ...str('my-pc')]), PC.mac)],
    [12, broadcast(67, 68, GW.ip, dhcp(2, 2, PC.ip, lease), GW.mac)],
    [3, broadcast(68, 67, '0.0.0.0', dhcp(1, 3, '0.0.0.0', [50, 4, ...ipBytes(PC.ip)]), PC.mac)],
    [9, broadcast(67, 68, GW.ip, dhcp(2, 5, PC.ip, lease), GW.mac)],
  ]);
}

const echo = (type: number, seq: number, data: Bytes) => cat([type, 0, 0, 0, ...be16(1), ...be16(seq)], data);

/** 네트워크 계층: 한 번에 보낼 수 있는 크기(MTU 1500)보다 큰 패킷이 조각으로 나뉜다 */
function buildIpFragment(): Uint8Array {
  ipId = 1;
  const MORE = 0x2000;
  const frames: Frames = [];
  // 작은 핑: 쪼갤 필요가 없다
  const small = str('abcdefghijklmnopqrstuvwabcdefghi');
  frames.push([0, out(1, GW.ip, echo(8, 1, small))], [2, inn(1, GW.ip, echo(0, 1, small), 64)]);
  // 큰 핑: 데이터 3000바이트. IP 헤더 20바이트를 빼면 조각 하나에 1480바이트까지 담긴다.
  const big = filler(3000, 5);
  const pieces = (message: Uint8Array, id: number, send: (piece: Uint8Array, frag: Frag) => Uint8Array, firstGap: number) => {
    for (let at = 0; at < message.length; at += 1480) {
      const last = at + 1480 >= message.length;
      frames.push([at === 0 ? firstGap : 0.05, send(message.subarray(at, at + 1480), { id, flags: (last ? 0 : MORE) | (at / 8) })]);
    }
  };
  pieces(echo(8, 2, big), 0x04d2, (piece, frag) => out(1, GW.ip, piece, 64, frag), 1000);
  pieces(echo(0, 2, big), 0x8ae1, (piece, frag) => inn(1, GW.ip, piece, 64, frag), 3);
  return toPcap(frames);
}

/** 네트워크 계층: TTL을 1부터 하나씩 늘려 가며 길목의 라우터를 차례로 알아낸다 */
function buildTraceroute(): Uint8Array {
  ipId = 1;
  const routers = [GW.ip, '10.45.0.1', '203.0.113.254'];
  const delays = [2, 9, 14, 21];
  const data = filler(32, 2);
  const frames: Frames = [];
  for (let hop = 1; hop <= 4; hop++) {
    const probe = ip4(PC.ip, WEB_IP, 1, echo(8, hop, data), hop);
    frames.push([hop === 1 ? 0 : 1000, eth(GW.mac, PC.mac, 0x0800, probe)]);
    // 수명이 다한 곳의 라우터가, 버린 패킷의 앞부분을 담아 알림을 돌려보낸다
    if (hop <= routers.length) frames.push([delays[hop - 1], inn(1, routers[hop - 1], [11, 0, 0, 0, 0, 0, 0, 0, ...probe.subarray(0, 28)], 256 - hop)]);
    else frames.push([delays[hop - 1], inn(1, WEB_IP, echo(0, hop, data), 52)]);
  }
  return toPcap(frames);
}

/** 링크 계층: IP 주소로 MAC 주소를 알아낸 뒤에야 같은 네트워크 안에서 보낼 수 있다 */
function buildArp(): Uint8Array {
  ipId = 1;
  const data = str('abcdefghijklmnopqrstuvwabcdefghi');
  return toPcap([
    [0, eth(BROADCAST, PC.mac, 0x0806, arp(1, PC.mac, PC.ip, '00:00:00:00:00:00', GW.ip))],
    [2, eth(PC.mac, GW.mac, 0x0806, arp(2, GW.mac, GW.ip, PC.mac, PC.ip))],
    [1, out(1, GW.ip, echo(8, 1, data))],
    [2, inn(1, GW.ip, echo(0, 1, data), 64)],
  ]);
}

export type SampleGroup = 'overview' | 'application' | 'transport' | 'network' | 'link';
export const SAMPLE_GROUPS: SampleGroup[] = ['overview', 'application', 'transport', 'network', 'link'];

/** 내장 샘플 목록. 제목과 설명은 언어별 사전(samples)에 같은 id로 들어 있다. */
export const SAMPLES: { id: string; group: SampleGroup; build: (bodyLine: string) => Uint8Array }[] = [
  { id: 'web-visit', group: 'overview', build: buildWebVisitSample },
  { id: 'trouble', group: 'overview', build: buildTroubleSample },
  { id: 'http-connections', group: 'application', build: buildHttpConnections },
  { id: 'http-cookie-cache', group: 'application', build: buildHttpCookieCache },
  { id: 'dns-records', group: 'application', build: buildDnsRecords },
  { id: 'udp-vs-tcp', group: 'transport', build: buildUdpVsTcp },
  { id: 'tcp-open-close', group: 'transport', build: buildTcpOpenClose },
  { id: 'tcp-retransmit', group: 'transport', build: buildTcpRetransmit },
  { id: 'tcp-flow-control', group: 'transport', build: buildTcpFlowControl },
  { id: 'dhcp', group: 'network', build: buildDhcp },
  { id: 'ip-fragment', group: 'network', build: buildIpFragment },
  { id: 'traceroute', group: 'network', build: buildTraceroute },
  { id: 'arp', group: 'link', build: buildArp },
];
