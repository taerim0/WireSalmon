import type { Messages } from '../i18n/index.ts';
import { createDissector, KNOWN_PORTS } from './dissect.ts';
import type { RawPacket } from './reader.ts';
import type { Flow, Packet } from './types.ts';

const SYN = 0x02;
const ACK = 0x10;
const FIN = 0x01;
const RST = 0x04;

/** DNS 답을 받고 이 시간(초) 안에 시작한 연결만 그 조회와 이어진 것으로 본다 */
const LOOKUP_WINDOW = 5;

/**
 * 이미 지나간 구간의 데이터가 이 시간(초) 안에 뒤따라오면 재전송이 아니라 순서가 바뀐 것으로 본다.
 * 재전송은 응답을 기다린 뒤에야 일어나므로 이렇게 빨리 올 수 없다. Wireshark와 같은 기준이다.
 */
const OUT_OF_ORDER_WINDOW = 0.003;

const isServerPort = (port: number) => port < 1024 || port in KNOWN_PORTS;
/** 순서 번호는 32비트에서 한 바퀴 돌 수 있어서 차이로 비교한다 */
const seqAtMost = (a: number, b: number) => ((b - a) | 0) >= 0;

/** 캡처 하나를 통째로 담는 그릇: 패킷을 해석하고 대화 단위로 묶는다 */
export class Session {
  packets: Packet[] = [];
  flows: Flow[] = [];
  /** DNS 답변 등에서 알아낸 IP → 이름 */
  names = new Map<string, string>();
  t0 = 0;
  /** 마지막 패킷의 시각. 아직 답이 없는지 판단하는 기준이 된다. */
  lastTs = 0;
  private byKey = new Map<string, Flow>();
  private raws: RawPacket[] = [];
  /** DNS 답변으로 알아낸 주소 → 그 조회에 걸린 시간 */
  private lookups = new Map<string, NonNullable<Flow['lookup']> & { ts: number }>();
  private queryTs = new Map<number, number>();
  private L: Messages;
  private dissect: ReturnType<typeof createDissector>;

  constructor(L: Messages) {
    this.L = L;
    this.dissect = createDissector(L);
  }

  /** 같은 캡처를 다른 언어로 다시 해석한다. 패킷 번호와 대화 번호는 그대로 유지된다. */
  relocalize(L: Messages) {
    const raws = this.raws;
    this.L = L;
    this.dissect = createDissector(L);
    this.packets = [];
    this.flows = [];
    this.names = new Map();
    this.byKey = new Map();
    this.lookups = new Map();
    this.queryTs = new Map();
    this.raws = [];
    for (const raw of raws) this.add(raw);
  }

  add(raw: RawPacket): Packet {
    const p = this.dissect(raw, this.packets.length + 1);
    this.raws.push(raw);
    if (this.packets.length === 0) this.t0 = raw.ts;
    this.packets.push(p);
    this.lastTs = raw.ts;
    // 같은 주소를 여러 사이트가 함께 쓰므로 가장 최근에 알게 된 이름을 따른다
    for (const [ip, name] of p.names ?? []) this.names.set(ip, name);

    let flow = this.byKey.get(p.flowKey);
    const synOnly = p.tcp !== undefined && (p.tcp.flags & (SYN | ACK)) === SYN;
    // 같은 포트 쌍을 다시 쓰는 새 연결
    if (flow?.tcp && synOnly && (flow.tcp.rst || flow.tcp.fin.a || flow.tcp.fin.b)) flow = undefined;
    if (!flow) {
      flow = this.createFlow(p);
      this.byKey.set(p.flowKey, flow);
      this.flows.push(flow);
    }

    p.flowId = flow.id;
    p.fromA = p.fromClient ?? (p.src === flow.a.addr && p.srcPort === flow.a.port);
    flow.packets.push(p);
    flow.bytes += p.origLen;
    flow.lastTs = p.ts;
    if (p.appLabel && (flow.app === 'TCP' || flow.app === 'UDP' || flow.app === p.proto)) flow.app = p.appLabel;
    if (p.host && !flow.host) flow.host = p.host;
    if (flow.tcp) this.tcpStep(flow, p);
    if (p.info?.dns) {
      if (!p.info.dns.response) {
        if (!this.queryTs.has(flow.id)) this.queryTs.set(flow.id, p.ts);
      } else {
        const asked = this.queryTs.get(flow.id);
        if (asked !== undefined) for (const [ip, name] of p.names ?? []) this.lookups.set(ip, { name, ms: (p.ts - asked) * 1000, flowId: flow.id, ts: p.ts });
      }
    }
    return p;
  }

  private createFlow(p: Packet): Flow {
    let a: Flow['a'] = { addr: p.src, port: p.srcPort, name: this.names.get(p.src) };
    let b: Flow['b'] = { addr: p.dst, port: p.dstPort, name: this.names.get(p.dst) };
    // 대화를 시작한 쪽을 왼쪽(a)에 둔다. 응답부터 캡처된 경우 뒤집는다.
    const synAck = p.tcp !== undefined && (p.tcp.flags & (SYN | ACK)) === (SYN | ACK);
    const looksLikeReply = p.srcPort !== undefined && p.dstPort !== undefined && isServerPort(p.srcPort) && !isServerPort(p.dstPort);
    const synOnly = p.tcp !== undefined && (p.tcp.flags & (SYN | ACK)) === SYN;
    if (synAck || (looksLikeReply && !synOnly)) [a, b] = [b, a];
    const flow: Flow = { id: this.flows.length + 1, key: p.flowKey, app: p.appLabel ?? p.proto, a, b, packets: [], bytes: 0, firstTs: p.ts, lastTs: p.ts };
    if (p.appLabel === 'DHCP') {
      flow.a = { addr: '', label: this.L.dhcp.client };
      flow.b = { addr: '', label: this.L.dhcp.server };
    }
    if (p.tcp || p.proto === 'QUIC') {
      // 바로 직전의 조회만 이 대화를 위한 것으로 본다
      const lookup = this.lookups.get(b.addr);
      if (lookup && p.ts - lookup.ts <= LOOKUP_WINDOW) flow.lookup = lookup;
    }
    if (p.tcp) flow.tcp = { syn: false, synAck: false, established: false, fin: { a: false, b: false }, rst: false, isn: {}, maxEnd: {}, maxEndTs: {}, dataBytes: 0, retransmits: 0, outOfOrder: 0 };
    return flow;
  }

  private tcpStep(flow: Flow, p: Packet) {
    const m = this.L.tcp;
    const s = flow.tcp!;
    const t = p.tcp!;
    const me = p.fromA ? 'a' : 'b';
    const peer = p.fromA ? 'b' : 'a';
    if (s.isn[me] === undefined) s.isn[me] = t.seq;
    if (t.flags & SYN && s.maxEnd[me] === undefined) s.maxEnd[me] = (t.seq + 1) >>> 0;

    const tcpLayer = p.layers.find((l) => l.id === 'tcp');
    if (tcpLayer) {
      const relSeq = (t.seq - s.isn[me]!) >>> 0;
      const relAck = t.flags & ACK && s.isn[peer] !== undefined ? (t.ack - s.isn[peer]!) >>> 0 : undefined;
      tcpLayer.fields.splice(3, 0, { label: m.relative, value: m.relativeValue(relSeq, relAck), help: m.relativeHelp });
    }

    // 연결 유지 확인(keep-alive): 이미 보낸 마지막 바이트 자리를 다시 찔러 본다. 재전송과 구별한다.
    const sent = s.maxEnd[me];
    const keepAlive = sent !== undefined && t.payloadLen <= 1 && !(t.flags & (SYN | FIN | RST)) && t.seq === (sent - 1) >>> 0;
    let retransmit = false;
    let outOfOrder = false;
    if (t.payloadLen > 0 && !keepAlive) {
      const end = (t.seq + t.payloadLen) >>> 0;
      if (s.maxEnd[me] !== undefined && seqAtMost(end, s.maxEnd[me]!)) {
        if (p.ts - (s.maxEndTs[me] ?? -Infinity) < OUT_OF_ORDER_WINDOW) {
          outOfOrder = true;
          s.outOfOrder++;
          s.dataBytes += t.payloadLen;
        } else {
          retransmit = true;
          s.retransmits++;
        }
      } else {
        s.maxEnd[me] = end;
        s.maxEndTs[me] = p.ts;
        s.dataBytes += t.payloadLen;
      }
    }

    if (t.flags & RST) {
      s.rst = true;
      p.stage = 'close';
      p.summary = m.rst;
    } else if (t.flags & SYN) {
      p.stage = 'open';
      if (t.flags & ACK) {
        s.synAck = true;
        p.summary = m.synAck;
      } else {
        p.summary = s.syn ? m.synRetry : m.syn;
        s.syn = true;
      }
    } else if (t.flags & FIN) {
      s.fin[me] = true;
      p.stage = 'close';
      if (t.payloadLen === 0) p.summary = m.fin;
    } else if (keepAlive) {
      p.stage = 'data';
      p.summary = m.keepAlive;
    } else if (t.payloadLen === 0) {
      if (s.synAck && !s.established && p.fromA) {
        s.established = true;
        p.stage = 'open';
        p.summary = m.established;
      } else {
        p.stage = s.fin.a || s.fin.b ? 'close' : 'data';
        p.summary = m.ackOnly;
      }
    } else {
      p.stage = 'data';
      if (!p.appLabel || p.layers.at(-1)?.id === 'data') {
        if (flow.app === 'HTTPS' || flow.app === 'TLS') p.summary = m.encryptedChunk(t.payloadLen);
        else if (flow.app === 'HTTP') p.summary = m.httpChunk(t.payloadLen);
      }
    }
    if (t.payloadLen > 0 && s.synAck) s.established = true;
    if (retransmit) p.summary = m.retransmit(p.summary);
    if (outOfOrder) p.summary = m.outOfOrder(p.summary);
  }
}
