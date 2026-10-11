import assert from 'node:assert/strict';
import { flowStatus, flowTitle } from '../src/core/describe.ts';
import { diagnose, problemOf } from '../src/core/diagnose.ts';
import { CaptureReader } from '../src/core/reader.ts';
import { buildTroubleSample, buildWebVisitSample } from '../src/core/sample.ts';
import { Session } from '../src/core/session.ts';
import { httpConversation, pairExchanges, parseHttp, reassemble } from '../src/core/stream.ts';
import type { Flow } from '../src/core/types.ts';
import { timing } from '../src/core/timing.ts';
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

const sample = buildWebVisitSample(en.sampleBodyLine);
const session = load(sample);
print(session);

assert.equal(session.packets.length, 42);
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
    assert.ok(!hangul.test(layer.name + layer.brief + layer.osi + layer.role), `${p.no}: ${layer.name}`);
    assert.ok(layer.brief, `${p.no}: ${layer.name} has no brief`);
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
assert.equal(switched.packets.length, 42);
assert.deepEqual(
  switched.packets.map((p) => p.summary),
  english.packets.map((p) => p.summary),
);
assert.deepEqual(
  switched.flows.map((f) => [f.id, f.a.label]),
  english.flows.map((f) => [f.id, f.a.label]),
);

// 진단: 잘 되는 샘플에서는 문제를 하나도 찾지 않아야 한다
for (const f of session.flows) assert.equal(problemOf(diagnose(f, session.names, ko, session.lastTs)), null, flowTitle(f, session.names, ko));
assert.equal(diagnose(http, session.names, ko, session.lastTs)[0].tone, 'ok');

// 시간 분해: 샘플을 만들 때 넣은 간격이 그대로 나와야 한다
const phase = (f: Session['flows'][number], kind: string) => Math.round(timing(f).phases.find((p) => p.kind === kind)?.ms ?? -1);
assert.equal(phase(session.flows[2], 'lookup'), 24);
assert.deepEqual([phase(http, 'dns'), phase(http, 'connect'), phase(http, 'wait')], [24, 18, 25]);
assert.deepEqual([phase(https, 'connect'), phase(https, 'tls')], [18, 22]);
assert.equal(phase(session.flows[6], 'rtt'), 23);
assert.equal(timing(session.flows[6]).phases[0].count, 2);

// 문제가 있는 샘플: 대화마다 기대한 진단이 나와야 한다
const trouble = load(buildTroubleSample(), undefined, en);
const verdicts = trouble.flows.map((f) => {
  const list = diagnose(f, trouble.names, en, trouble.lastTs);
  console.log(`[${f.app}] ${flowTitle(f, trouble.names, en)}`);
  for (const finding of list) console.log(`    ${finding.tone.padEnd(4)} ${finding.title}`);
  const t = timing(f);
  if (t.phases.length) console.log('    time', t.phases.map((p) => `${p.kind}=${en.timing.duration(p.ms)}${p.slow ? ' (slow)' : ''}`).join(', '));
  return [f.app, problemOf(list), list[0]?.title ?? ''] as const;
});
assert.deepEqual(
  verdicts.map(([app, problem]) => [app, problem]),
  [
    ['DNS', 'warn'], // 없는 이름
    ['TCP', 'bad'], // 연결 거부
    ['TCP', 'bad'], // 응답 없음
    ['PING', 'bad'],
    ['ARP', null], // 답이 안 보여도 다른 장비의 질문일 수 있어 문제로 단정하지 않는다
    ['DNS', 'bad'], // 답 없는 DNS 서버
    ['DNS', null],
    ['HTTP', 'warn'], // 연결은 됐지만 서버가 느림
    ['DNS', null],
    ['HTTP', 'bad'], // 500
    ['HTTP', 'warn'], // 404
    ['TCP', 'warn'], // 재전송 뒤 강제 종료
  ],
);
assert.match(verdicts[1][2], /refused \(port 8080\)/);
assert.match(verdicts[2][2], /No answer.*3 connection requests/);
assert.match(verdicts[7][2], /Slow: waiting for the server took 1\.85 s/);
assert.match(verdicts[9][2], /500/);
assert.match(verdicts[11][2], /cut the connection abruptly/);

const slow = timing(trouble.flows[7]);
assert.deepEqual(
  slow.phases.map((p) => [p.kind, Math.round(p.ms), p.slow, p.verySlow]),
  [
    ['dns', 180, true, false],
    ['connect', 18, false, false],
    ['wait', 1850, true, true],
  ],
);
assert.equal(slow.slowest?.kind, 'wait');

// 방금 보낸 요청은 아직 "응답 없음"이 아니다
const fresh = trouble.flows[2];
assert.equal(problemOf(diagnose({ ...fresh, packets: fresh.packets.slice(0, 1) }, trouble.names, en, fresh.firstTs + 0.2)), null);

// HTTP 메시지 이어 읽기: 헤더와 본문이 다른 패킷에 와도 하나의 응답으로 읽는다
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const bytesOf = (s: string) => new TextEncoder().encode(s);
const talk = httpConversation(http);
assert.equal(talk.exchanges.length, 1);
assert.equal(talk.exchanges[0].request?.startLine, 'GET / HTTP/1.1');
const reply = talk.exchanges[0].response!;
assert.deepEqual([reply.status, reply.state, reply.declared, reply.body.length], [200, 'complete', 170, 170]);
assert.deepEqual([reply.headerPackets, reply.bodyPackets], [[14], [15]]);
assert.match(text(reply.body), /^<!doctype html>[\s\S]*<\/html>\n$/);
const notFound = httpConversation(trouble.flows[10]).exchanges[0];
assert.deepEqual([notFound.request?.path, notFound.response?.status, text(notFound.response!.body)], ['/old-page', 404, 'no such page\n']);
assert.equal(httpConversation(trouble.flows[1]).exchanges.length, 0);

// 순서가 바뀐 조각은 제자리에 넣고, 다시 온 조각은 버린다
const whole = bytesOf('HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789');
const piece = (from: number, to: number, no: number) => ({ offset: 1 + from, data: whole.subarray(from, to), no });
const shuffled = reassemble([piece(30, 49, 3), piece(0, 20, 1), piece(10, 30, 2), piece(0, 20, 4)], 1);
assert.equal(text(shuffled.data), text(whole));
assert.deepEqual([shuffled.stopped, shuffled.pieces.map((p) => p.no)], [undefined, [1, 2, 3]]);
const joined = parseHttp(shuffled, 'response')[0];
assert.deepEqual([joined.state, text(joined.body), joined.headerPackets, joined.bodyPackets], ['complete', '0123456789', [1, 2, 3], [3]]);

// 중간 조각이 없으면 그 앞까지만 잇고 불완전하다고 알린다
const holed = reassemble([piece(0, 42, 1), piece(46, 49, 3)], 1);
assert.equal(holed.stopped, 'gap');
const partial = parseHttp(holed, 'response')[0];
assert.deepEqual([partial.state, text(partial.body), partial.declared], ['cut', '012', 10]);

// 조각(chunked) 전송과 이어지는 두 번째 메시지
const chunkedStream = reassemble([{ offset: 0, no: 1, data: bytesOf('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWire\r\n6\r\nSalmon\r\n0\r\n\r\nHTTP/1.1 304 Not Modified\r\n\r\n') }], 0);
const [first, second] = parseHttp(chunkedStream, 'response');
assert.deepEqual([first.state, first.chunked, text(first.body)], ['complete', true, 'WireSalmon']);
assert.deepEqual([second.status, second.body.length], [304, 0]);

// 길이를 알리지 않은 응답은 끝까지를 본문으로 본다
const open = parseHttp(reassemble([{ offset: 0, no: 1, data: bytesOf('HTTP/1.0 200 OK\r\n\r\nabc') }], 0), 'response')[0];
assert.deepEqual([open.state, text(open.body)], ['until-close', 'abc']);

// HEAD에 대한 응답은 길이를 알려도 본문이 없다: 다음 응답을 본문으로 삼키면 안 된다
const twoReplies = reassemble([{ offset: 0, no: 1, data: bytesOf('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello') }], 0);
const afterHead = parseHttp(twoReplies, 'response', ['HEAD', 'GET']);
assert.deepEqual(afterHead.map((r) => text(r.body)), ['', 'hello']);

// 100 Continue 같은 중간 응답은 같은 요청에 붙고, 짝을 밀어내지 않는다
const withInterim = parseHttp(reassemble([{ offset: 0, no: 1, data: bytesOf('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok') }], 0), 'response', ['POST', 'GET']);
const asked = parseHttp(reassemble([{ offset: 0, no: 1, data: bytesOf('POST /a HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET /b HTTP/1.1\r\n\r\n') }], 0), 'request');
const paired = pairExchanges(asked, withInterim);
assert.deepEqual(
  paired.map((x) => [x.request?.path, x.interim.map((r) => r.status), x.response?.status]),
  [
    ['/a', [100], 201],
    ['/b', [], 200],
  ],
);

// 앞부분만 저장된 패킷: 원래 길이를 알고, 본문이 잘린 까닭을 정확히 말한다
const fullReply = session.packets[14];
const snapped = new Session(en);
for (const p of http.packets) snapped.add({ ts: p.ts, linkType: 1, data: p.no === 15 ? p.data.subarray(0, p.data.length - 100) : p.data, origLen: p.origLen });
const snappedReply = snapped.packets.find((p) => p.tcp && p.tcp.captured < p.tcp.payloadLen)!;
assert.deepEqual([snappedReply.tcp!.payloadLen, snappedReply.tcp!.captured], [fullReply.tcp!.payloadLen, fullReply.tcp!.payloadLen - 100]);
assert.equal(snapped.flows[0].tcp!.dataBytes, http.tcp!.dataBytes);
const snappedBody = httpConversation(snapped.flows[0]).exchanges[0].response!;
assert.deepEqual([snappedBody.state, snappedBody.cutBy, snappedBody.body.length], ['cut', 'short', 70]);

// 연결 요청이 b 쪽에서만 온 대화를 진단해도 죽지 않는다
const stray = { ...trouble.flows[2], packets: trouble.flows[2].packets.map((p) => ({ ...p, fromA: false })) } as Flow;
assert.equal(diagnose(stray, trouble.names, en, trouble.lastTs)[0].tone, 'bad');
assert.match(session.flows[3].packets[0].summary, /^①/);

console.log('all checks passed');
