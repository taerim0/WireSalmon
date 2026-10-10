import assert from 'node:assert/strict';
import { flowStatus, flowTitle } from '../src/core/describe.ts';
import { CaptureReader } from '../src/core/reader.ts';
import { buildWebVisitSample } from '../src/core/sample.ts';
import { Session } from '../src/core/session.ts';
import { en } from '../src/i18n/en.ts';
import { ko } from '../src/i18n/ko.ts';

function load(bytes: Uint8Array, chunkSize = bytes.length, L = ko): Session {
  const reader = new CaptureReader();
  const session = new Session(L);
  for (let o = 0; o < bytes.length; o += chunkSize) for (const raw of reader.push(bytes.subarray(o, o + chunkSize))) session.add(raw);
  return session;
}

function print(session: Session, L = ko) {
  for (const p of session.packets) console.log(String(p.no).padStart(3), p.proto.padEnd(6), p.fromA ? '→' : '←', p.summary);
  console.log();
  for (const f of session.flows) console.log(`[${f.app}] ${flowTitle(f, session.names, L)} — ${f.packets.length}`, flowStatus(f, L).map((c) => c.label).join(' / '));
  console.log();
}

const sample = buildWebVisitSample(en.sample.bodyLine);
const session = load(sample);
print(session);

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

// 영어: 같은 캡처가 영어 문장으로 풀리고, 구조(대화 묶음·단계)는 언어와 무관해야 한다
const english = load(sample, sample.length, en);
print(english, en);
assert.deepEqual(
  english.flows.map((f) => [f.app, f.packets.length]),
  session.flows.map((f) => [f.app, f.packets.length]),
);
assert.deepEqual(
  english.packets.map((p) => p.stage),
  session.packets.map((p) => p.stage),
);
assert.match(english.flows[3].packets[0].summary, /^① Connection request/);
assert.match(english.flows[3].packets[3].summary, /^GET \/ — fetch request/);
assert.equal(flowTitle(english.flows[2], english.names, en), 'Name lookup: example.com');

// 영어로 열었을 때 한국어 문장이 한 군데도 남아 있으면 안 된다
const hangul = /[가-힣]/;
for (const p of english.packets) {
  assert.ok(!hangul.test(p.summary), `${p.no}: ${p.summary}`);
  for (const layer of p.layers) {
    assert.ok(!hangul.test(layer.name + layer.osi + layer.role), `${p.no}: ${layer.name}`);
    for (const field of layer.fields) assert.ok(!hangul.test(field.label + field.value + (field.help ?? '')), `${p.no}: ${field.label}`);
  }
}
for (const f of english.flows) {
  assert.ok(!hangul.test(flowTitle(f, english.names, en) + (f.a.label ?? '') + (f.b.label ?? '')));
  assert.ok(!hangul.test(flowStatus(f, en).map((c) => c.label).join('')));
}

// 열어 둔 캡처의 언어를 바꾸면 처음부터 그 언어로 연 것과 같아야 한다
const switched = load(sample);
switched.relocalize(en);
assert.equal(switched.packets.length, 41);
assert.deepEqual(
  switched.packets.map((p) => p.summary),
  english.packets.map((p) => p.summary),
);
assert.deepEqual(
  switched.flows.map((f) => [f.id, f.a.label]),
  english.flows.map((f) => [f.id, f.a.label]),
);

console.log('all checks passed');
