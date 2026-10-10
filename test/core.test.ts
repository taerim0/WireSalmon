import assert from 'node:assert/strict';
import { flowStatus, flowTitle } from '../src/core/describe.ts';
import { CaptureReader } from '../src/core/reader.ts';
import { buildWebVisitSample } from '../src/core/sample.ts';
import { Session } from '../src/core/session.ts';

function load(bytes: Uint8Array, chunkSize = bytes.length): Session {
  const reader = new CaptureReader();
  const session = new Session();
  for (let o = 0; o < bytes.length; o += chunkSize) for (const raw of reader.push(bytes.subarray(o, o + chunkSize))) session.add(raw);
  return session;
}

const sample = buildWebVisitSample();
const session = load(sample);

for (const p of session.packets) console.log(String(p.no).padStart(3), p.proto.padEnd(6), p.fromA ? '→' : '←', p.summary);
console.log();
for (const f of session.flows) console.log(`[${f.app}] ${flowTitle(f, session.names)} — ${f.packets.length}개`, flowStatus(f).map((c) => c.label).join(' / '));

assert.equal(session.packets.length, 41);
assert.ok(session.packets.every((p) => !p.truncated));
assert.deepEqual(
  session.flows.map((f) => f.app),
  ['DHCP', 'ARP', 'DNS', 'HTTP', 'DNS', 'HTTPS', 'PING'],
);
assert.equal(session.names.get('93.184.216.34'), 'example.com');

const http = session.flows[3];
assert.equal(http.host, 'example.com');
assert.deepEqual(http.tcp && [http.tcp.established, http.tcp.fin.a, http.tcp.fin.b, http.tcp.retransmits], [true, true, true, 0]);
assert.deepEqual(http.packets.slice(0, 3).map((p) => p.stage), ['open', 'open', 'open']);
assert.match(http.packets[2].summary, /^③/);
assert.match(http.packets[3].summary, /^GET \//);
assert.match(http.packets[5].summary, /^200 OK/);

const https = session.flows[5];
assert.equal(https.host, 'secure.example.com');
assert.match(https.packets[3].summary, /Client Hello.*secure\.example\.com/);

// 실시간 캡처처럼 잘게 쪼개 넣어도 결과가 같아야 한다
const streamed = load(sample, 7);
assert.deepEqual(
  streamed.packets.map((p) => p.summary),
  session.packets.map((p) => p.summary),
);

// pcapng (리틀 엔디언, 인터페이스 1개, 패킷 1개)
const frame = session.packets[4].data;
const pad = (4 - (frame.length % 4)) % 4;
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
const epbLen = 32 + frame.length + pad;
const pcapng = new Uint8Array([
  ...[0x0a, 0x0d, 0x0d, 0x0a], ...le32(28), ...[0x4d, 0x3c, 0x2b, 0x1a], 1, 0, 0, 0, ...le32(0xffffffff), ...le32(0xffffffff), ...le32(28),
  ...le32(1), ...le32(20), 1, 0, 0, 0, ...le32(0), ...le32(20),
  ...le32(6), ...le32(epbLen), ...le32(0), ...le32(0x0006_0000), ...le32(0), ...le32(frame.length), ...le32(frame.length), ...frame, ...new Array(pad).fill(0), ...le32(epbLen),
]);
const ng = load(pcapng, 5);
assert.equal(ng.packets.length, 1);
assert.equal(ng.packets[0].proto, 'ARP');

console.log('\n모든 검사 통과');
