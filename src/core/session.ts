import type { Messages } from '../i18n/index.ts';
import { createDissector, KNOWN_PORTS } from './dissect.ts';
import type { RawPacket } from './reader.ts';
import type { Flow, Packet } from './types.ts';

const SYN = 0x02;
const ACK = 0x10;
const FIN = 0x01;
const RST = 0x04;

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
  private byKey = new Map<string, Flow>();
  private raws: RawPacket[] = [];
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
    this.raws = [];
    for (const raw of raws) this.add(raw);
  }

  add(raw: RawPacket): Packet {
    const p = this.dissect(raw, this.packets.length + 1);
    this.raws.push(raw);
    if (this.packets.length === 0) this.t0 = raw.ts;
    this.packets.push(p);
    for (const [ip, name] of p.names ?? []) if (!this.names.has(ip)) this.names.set(ip, name);

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
    return p;
  }

  private createFlow(p: Packet): Flow {
    let a = { addr: p.src, port: p.srcPort };
    let b = { addr: p.dst, port: p.dstPort };
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
    if (p.tcp) flow.tcp = { syn: false, synAck: false, established: false, fin: { a: false, b: false }, rst: false, isn: {}, maxEnd: {}, dataBytes: 0, retransmits: 0 };
    return flow;
  }

  private tcpStep(flow: Flow, p: Packet) {
    const m = this.L.tcp;
    const s = flow.tcp!;
    const t = p.tcp!;
    const me = p.fromA ? 'a' : 'b';
    const peer = p.fromA ? 'b' : 'a';
    if (s.isn[me] === undefined) s.isn[me] = t.seq;

    const tcpLayer = p.layers.find((l) => l.id === 'tcp');
    if (tcpLayer) {
      const relSeq = (t.seq - s.isn[me]!) >>> 0;
      const relAck = t.flags & ACK && s.isn[peer] !== undefined ? (t.ack - s.isn[peer]!) >>> 0 : undefined;
      tcpLayer.fields.splice(3, 0, { label: m.relative, value: m.relativeValue(relSeq, relAck), help: m.relativeHelp });
    }

    let retransmit = false;
    if (t.payloadLen > 0) {
      const end = (t.seq + t.payloadLen) >>> 0;
      if (s.maxEnd[me] !== undefined && seqAtMost(end, s.maxEnd[me]!)) {
        retransmit = true;
        s.retransmits++;
      } else {
        s.maxEnd[me] = end;
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
  }
}
