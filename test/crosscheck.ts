// WireSalmon의 해석 결과를 Wireshark(tshark)의 해석 결과와 패킷 단위로 대조한다.
// 사용: npm run crosscheck -- <pcap 파일> [--examples]
// Wireshark가 설치되어 있어야 한다. tshark가 다른 곳에 있으면 WIRESALMON_TSHARK에 경로를 넣는다.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { findings } from '../src/core/diagnose.ts';
import { CaptureReader } from '../src/core/reader.ts';
import { Session } from '../src/core/session.ts';
import { ko } from '../src/i18n/ko.ts';

const file = process.argv[2];
const showExamples = process.argv.includes('--examples');
const TSHARK = process.env.WIRESALMON_TSHARK ?? (process.platform === 'win32' ? 'C:/Program Files/Wireshark/tshark.exe' : 'tshark');
if (!file) {
  console.error('usage: npm run crosscheck -- <capture file> [--examples]');
  process.exit(1);
}

const FIELDS = [
  'frame.number', 'frame.time_relative', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
  'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
  'tcp.flags', 'tcp.seq_raw', 'tcp.ack_raw', 'tcp.len', 'tcp.stream', 'udp.stream',
  'tcp.analysis.retransmission', 'tcp.analysis.fast_retransmission', 'tcp.analysis.spurious_retransmission',
  'tcp.analysis.out_of_order', 'tcp.analysis.keep_alive',
  'dns.flags.response', 'dns.flags.rcode', 'dns.qry.name', 'dns.count.answers',
  'http.request.method', 'http.response.code',
  'tls.handshake.type', 'tls.handshake.extensions_server_name', 'tls.record.content_type',
  'icmp.type', 'icmpv6.type', 'arp.opcode', 'dhcp.option.dhcp', '_ws.col.protocol',
  'ip.ttl', 'ip.frag_offset', 'quic.header_form', 'eth.src', 'eth.dst', 'tcp.seq', 'tcp.ack',
];

const out = execFileSync(
  TSHARK,
  [
    '-r', file, '-n', '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=a', '-E', 'aggregator=,',
    // 우리는 패킷 하나씩 해석하므로 tshark도 조각을 합치지 않게 한다
    '-o', 'tcp.desegment_tcp_streams:FALSE', '-o', 'tls.desegment_ssl_records:FALSE',
    '-o', 'http.desegment_headers:FALSE', '-o', 'http.desegment_body:FALSE',
    ...FIELDS.flatMap((f) => ['-e', f]),
  ],
  { encoding: 'utf8', maxBuffer: 1 << 30 },
);
const theirs = out.split(/\r?\n/).filter(Boolean).map((line) => Object.fromEntries(line.split('\t').map((v, i) => [FIELDS[i], v])));

const session = new Session(ko);
const reader = new CaptureReader();
for (const raw of reader.push(new Uint8Array(readFileSync(file)))) session.add(raw);

const stats = new Map<string, { checked: number; bad: number; examples: string[] }>();
function check(name: string, applies: boolean, ok: boolean, example: () => string) {
  if (!applies) return;
  const s = stats.get(name) ?? { checked: 0, bad: 0, examples: [] };
  s.checked++;
  if (!ok) {
    s.bad++;
    if (s.examples.length < 6) s.examples.push(example());
  }
  stats.set(name, s);
}
const first = (v: string) => v.split(',')[0];
const has = (v: string | undefined) => v !== undefined && v !== '';
const RETRANS = '[재전송]';

console.log(`packets: ours ${session.packets.length}, tshark ${theirs.length}`);
const streamToFlow = new Map<string, number>();
const flowToStream = new Map<number, string>();
const protoPairs = new Map<string, number>();

for (let i = 0; i < Math.min(session.packets.length, theirs.length); i++) {
  const p = session.packets[i];
  const t = theirs[i];
  const flow = session.flows[p.flowId! - 1];
  const no = t['frame.number'];
  const ex = (ours: unknown, theirsValue: unknown) => () => `#${no} ours=${ours} tshark=${theirsValue}`;

  check('time', true, Math.abs(p.ts - session.t0 - Number(t['frame.time_relative'])) < 2e-6, ex(p.ts - session.t0, t['frame.time_relative']));

  const isIp = has(t['ip.src']) || has(t['ipv6.src']);
  const tSrc = first(t['ip.src'] || t['ipv6.src']);
  const tDst = first(t['ip.dst'] || t['ipv6.dst']);
  const isArp = has(t['arp.opcode']);
  // ICMP 오류 패킷은 안에 원래 패킷이 들어 있어 tshark가 주소를 두 개씩 낸다: 첫 번째가 바깥쪽
  check('ip addresses', isIp && !isArp, p.src === tSrc && p.dst === tDst, ex(`${p.src}>${p.dst}`, `${tSrc}>${tDst}`));
  check('ip ttl', has(t['ip.ttl']), p.layers.find((l) => l.id === 'ipv4')?.fields[2].value === first(t['ip.ttl']), ex(p.layers.find((l) => l.id === 'ipv4')?.fields[2].value, t['ip.ttl']));

  const fragment = Number(first(t['ip.frag_offset'] || '0')) > 0;
  const isTcp = has(t['tcp.srcport']) && !has(t['icmp.type']) && !has(t['icmpv6.type']) && !fragment;
  const isUdp = has(t['udp.srcport']) && !has(t['icmp.type']) && !has(t['icmpv6.type']) && !fragment;
  check('tcp ports', isTcp, String(p.srcPort) === first(t['tcp.srcport']) && String(p.dstPort) === first(t['tcp.dstport']), ex(`${p.srcPort}>${p.dstPort}`, `${t['tcp.srcport']}>${t['tcp.dstport']}`));
  check('udp ports', isUdp, String(p.srcPort) === first(t['udp.srcport']) && String(p.dstPort) === first(t['udp.dstport']), ex(`${p.srcPort}>${p.dstPort}`, `${t['udp.srcport']}>${t['udp.dstport']}`));
  check('tcp recognised', isTcp, p.tcp !== undefined, ex(p.proto, 'TCP'));

  if (isTcp && p.tcp) {
    const flags = Number(first(t['tcp.flags']));
    check('tcp flags', true, (p.tcp.flags & 0x3f) === (flags & 0x3f), ex(p.tcp.flags.toString(16), flags.toString(16)));
    check('tcp seq', true, String(p.tcp.seq) === first(t['tcp.seq_raw']), ex(p.tcp.seq, t['tcp.seq_raw']));
    check('tcp ack', (flags & 0x10) !== 0, String(p.tcp.ack) === first(t['tcp.ack_raw']), ex(p.tcp.ack, t['tcp.ack_raw']));
    check('tcp payload length', true, String(p.tcp.payloadLen) === first(t['tcp.len']), ex(p.tcp.payloadLen, t['tcp.len']));

    // 상대 번호: tshark는 SYN을 못 본 연결의 첫 패킷을 1로 세고 우리는 0으로 센다. SYN을 본 연결만 그대로 비교한다.
    const me = p.fromA ? 'a' : 'b';
    if (flow.tcp!.syn && flow.tcp!.synAck) {
      const rel = (p.tcp.seq - flow.tcp!.isn[me]!) >>> 0;
      check('tcp captured length', true, p.tcp.captured <= p.tcp.payloadLen, ex(p.tcp.captured, p.tcp.payloadLen));
      check('tcp relative seq', true, String(rel) === first(t['tcp.seq']), ex(rel, t['tcp.seq']));
    }

    const oursRe = p.summary.startsWith(RETRANS);
    const theirRe = has(t['tcp.analysis.retransmission']) || has(t['tcp.analysis.fast_retransmission']) || has(t['tcp.analysis.spurious_retransmission']);
    const theirOoo = has(t['tcp.analysis.out_of_order']);
    check('retransmission: we flag, tshark agrees', oursRe, theirRe, ex('retrans', theirOoo ? 'out-of-order' : 'none'));
    check('retransmission: tshark flags, we agree', theirRe && p.tcp.payloadLen > 0, oursRe, ex('none', 'retrans'));
    const oursOoo = p.summary.startsWith('[순서 바뀜]');
    check('out-of-order: tshark flags, we agree', theirOoo, oursOoo, ex(oursRe ? 'retrans' : 'none', 'out-of-order'));
    check('out-of-order: we flag, tshark agrees', oursOoo, theirOoo, ex('out-of-order', theirRe ? 'retrans' : 'none'));
    const oursKa = p.summary === ko.tcp.keepAlive;
    check('keep-alive: tshark flags, we agree', has(t['tcp.analysis.keep_alive']), oursKa, ex(p.summary, 'keep-alive'));
    check('keep-alive: we flag, tshark agrees', oursKa, has(t['tcp.analysis.keep_alive']), ex('keep-alive', t['_ws.col.protocol']));

    const stream = `tcp${t['tcp.stream']}`;
    if (!streamToFlow.has(stream)) streamToFlow.set(stream, p.flowId!);
    if (!flowToStream.has(p.flowId!)) flowToStream.set(p.flowId!, stream);
    check('tcp conversation grouping', true, streamToFlow.get(stream) === p.flowId && flowToStream.get(p.flowId!) === stream, ex(`flow ${p.flowId}`, stream));
  }

  // DNS / mDNS / LLMNR (UDP만: TCP 위의 DNS는 우리가 해석하지 않는다)
  const tDns = has(t['dns.flags.response']) && (isUdp || isTcp);
  check('dns recognised', tDns, p.info?.dns !== undefined, ex(p.proto, t['_ws.col.protocol']));
  check('dns: we say dns, tshark agrees', p.info?.dns !== undefined, has(t['dns.flags.response']), ex(p.proto, t['_ws.col.protocol']));
  if (tDns && p.info?.dns) {
    const response = first(t['dns.flags.response']) === 'True' || first(t['dns.flags.response']) === '1';
    check('dns direction', true, p.info.dns.response === response, ex(p.info.dns.response, t['dns.flags.response']));
    check('dns result code', response, String(p.info.dns.rcode) === first(t['dns.flags.rcode']), ex(p.info.dns.rcode, t['dns.flags.rcode']));
    check('dns answer count', true, String(p.info.dns.answers) === first(t['dns.count.answers']), ex(p.info.dns.answers, t['dns.count.answers']));
    check('dns name', has(t['dns.qry.name']), (p.host ?? '') === first(t['dns.qry.name']), ex(p.host, first(t['dns.qry.name'])));
  }

  const tMethod = first(t['http.request.method'] ?? '');
  const tCode = first(t['http.response.code'] ?? '');
  check('http request', has(tMethod) && isTcp, p.info?.http?.method === tMethod, ex(p.info?.http?.method, tMethod));
  check('http status', has(tCode) && isTcp, String(p.info?.http?.status) === tCode, ex(p.info?.http?.status, tCode));
  check('http: we say http, tshark agrees', p.info?.http !== undefined, has(tMethod) || has(tCode), ex(p.summary.slice(0, 40), t['_ws.col.protocol']));

  const hsTypes = (t['tls.handshake.type'] ?? '').split(',').filter(Boolean);
  const tlsHere = has(t['tls.record.content_type']) && isTcp;
  check('tls recognised (record starts this packet)', tlsHere, p.layers.some((l) => l.id === 'tls'), ex(p.proto, t['_ws.col.protocol']));
  check('tls: we say tls, tshark agrees', p.layers.some((l) => l.id === 'tls'), has(t['tls.record.content_type']), ex(p.summary.slice(0, 40), t['_ws.col.protocol']));
  check('tls client hello', hsTypes.includes('1') && isTcp, p.info?.tlsHello === 'client', ex(p.info?.tlsHello, hsTypes.join('+')));
  check('tls server hello', hsTypes[0] === '2' && isTcp, p.info?.tlsHello === 'server', ex(p.info?.tlsHello, hsTypes.join('+')));
  check('tls: we say hello, tshark agrees', p.info?.tlsHello !== undefined, hsTypes.includes(p.info?.tlsHello === 'client' ? '1' : '2'), ex(p.info?.tlsHello, hsTypes.join('+')));
  check('tls site name (SNI)', has(t['tls.handshake.extensions_server_name']) && isTcp, p.host === first(t['tls.handshake.extensions_server_name']), ex(p.host, t['tls.handshake.extensions_server_name']));

  check('icmp type', has(t['icmp.type']), String(p.info?.icmp?.type) === first(t['icmp.type']), ex(p.info?.icmp?.type, t['icmp.type']));
  check('icmpv6 type', has(t['icmpv6.type']), String(p.info?.icmp?.type) === first(t['icmpv6.type']), ex(p.info?.icmp?.type, t['icmpv6.type']));
  check('arp kind', isArp, (p.info?.arp === 'request' ? '1' : p.info?.arp === 'reply' ? '2' : '?') === first(t['arp.opcode']), ex(p.info?.arp, t['arp.opcode']));
  check('dhcp message', has(t['dhcp.option.dhcp']), String(p.info?.dhcp) === first(t['dhcp.option.dhcp']), ex(p.info?.dhcp, t['dhcp.option.dhcp']));
  check('quic: we say quic, tshark agrees', p.proto === 'QUIC', has(t['quic.header_form']), ex('QUIC', t['_ws.col.protocol']));
  check('quic: tshark says quic, we agree', has(t['quic.header_form']), p.proto === 'QUIC', ex(p.proto, 'QUIC'));
  check('ethernet addresses', has(t['eth.src']), p.layers[0]?.id !== 'eth' || (p.layers[0].brief === `${t['eth.src']} → ${t['eth.dst']}`), ex(p.layers[0]?.brief, `${t['eth.src']} → ${t['eth.dst']}`));

  const pair = `${p.proto} | ${t['_ws.col.protocol']}`;
  protoPairs.set(pair, (protoPairs.get(pair) ?? 0) + 1);
}

console.log('\ncheck'.padEnd(64), 'checked', ' mismatches');
for (const [name, s] of stats) {
  console.log(name.padEnd(63), String(s.checked).padStart(7), String(s.bad).padStart(11));
  if (showExamples) for (const e of s.examples) console.log('      ', e);
}
console.log('\nprotocol label: ours | tshark');
for (const [pair, n] of [...protoPairs].sort((a, b) => b[1] - a[1]).slice(0, 40)) console.log(String(n).padStart(6), pair);
const tones = new Map<string, number>();
for (const f of session.flows) {
  const list = findings(f, session.names, ko, session.lastTs);
  // 이름과 주소는 빼고 판정 종류만 센다
  for (const finding of list) {
    const key = `${finding.tone.padEnd(4)} [${f.app}] ${finding.title.replace(/[0-9a-z.:-]{4,}/gi, '~')}`;
    tones.set(key, (tones.get(key) ?? 0) + 1);
  }
}
console.log('\ndiagnosis verdicts');
for (const [key, n] of [...tones].sort()) console.log(String(n).padStart(5), key);
console.log(`\nflows: ${session.flows.length}, truncated packets: ${session.packets.filter((p) => p.truncated).length}`);
