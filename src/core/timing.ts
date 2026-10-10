import type { Flow, Packet } from './types.ts';

export type PhaseKind = 'dns' | 'connect' | 'tls' | 'wait' | 'download' | 'exchange' | 'lookup' | 'rtt' | 'arp' | 'dhcp';

/** 대화 안에서 시간이 쓰인 구간 하나 */
export interface Phase {
  kind: PhaseKind;
  ms: number;
  slow: boolean;
  /** 기준의 몇 배를 넘어서, 문제로 알릴 만큼 느림 */
  verySlow: boolean;
  /** 왕복 시간처럼 여러 번 잰 값일 때 */
  count?: number;
  min?: number;
  max?: number;
}

export interface Timing {
  phases: Phase[];
  /** 첫 패킷부터 마지막 패킷까지 */
  totalMs: number;
  slowest?: Phase;
}

/** 이 값(ms)을 넘으면 느리다고 표시한다. 없는 구간은 길어도 이상한 게 아니다. */
const SLOW: Partial<Record<PhaseKind, number>> = { dns: 100, lookup: 100, connect: 200, tls: 300, wait: 500, rtt: 100 };
const VERY_SLOW_FACTOR = 3;

const SYN = 0x02;
const ACK = 0x10;

const ms = (from: Packet, to: Packet) => (to.ts - from.ts) * 1000;

/** 대화가 어디에 시간을 썼는지 구간별로 나눈다 */
export function timing(flow: Flow): Timing {
  const phases: Phase[] = [];
  const add = (kind: PhaseKind, value: number, extra?: Partial<Phase>) => {
    const limit = SLOW[kind] ?? Infinity;
    if (value >= 0) phases.push({ kind, ms: value, slow: value > limit, verySlow: value > limit * VERY_SLOW_FACTOR, ...extra });
  };
  const packets = flow.packets;
  const first = (test: (p: Packet) => unknown, from = 0) => {
    for (let i = from; i < packets.length; i++) if (test(packets[i])) return i;
    return -1;
  };

  if (flow.tcp) {
    if (flow.lookup) add('dns', flow.lookup.ms);
    const syn = first((p) => p.fromA && p.tcp && (p.tcp.flags & (SYN | ACK)) === SYN);
    const synAck = syn < 0 ? -1 : first((p) => !p.fromA && p.tcp && (p.tcp.flags & (SYN | ACK)) === (SYN | ACK), syn);
    if (synAck >= 0) add('connect', ms(packets[syn], packets[synAck]));

    const hello = first((p) => p.info?.tlsHello === 'client');
    const helloBack = hello < 0 ? -1 : first((p) => p.info?.tlsHello === 'server', hello);
    if (helloBack >= 0) add('tls', ms(packets[hello], packets[helloBack]));

    const request = first((p) => p.info?.http?.method);
    if (request >= 0) {
      // 첫 요청 하나를 기준으로: 서버가 답을 시작하기까지, 그리고 답을 다 받기까지
      const reply = first((p) => !p.fromA && p.tcp?.payloadLen, request);
      if (reply >= 0) {
        add('wait', ms(packets[request], packets[reply]));
        const nextRequest = first((p) => p.info?.http?.method, reply);
        let last = reply;
        for (let i = reply; i < (nextRequest < 0 ? packets.length : nextRequest); i++) if (!packets[i].fromA && packets[i].tcp?.payloadLen) last = i;
        if (last > reply) add('download', ms(packets[reply], packets[last]));
      }
    } else {
      const start = helloBack >= 0 ? helloBack : first((p) => p.tcp?.payloadLen);
      let last = -1;
      for (let i = packets.length - 1; i > start && last < 0; i--) if (packets[i].tcp?.payloadLen) last = i;
      if (start >= 0 && last > start) add('exchange', ms(packets[start], packets[last]));
    }
  } else if (flow.app === 'DNS') {
    const query = first((p) => p.info?.dns && !p.info.dns.response);
    const answer = query < 0 ? -1 : first((p) => p.info?.dns?.response, query);
    if (answer >= 0) add('lookup', ms(packets[query], packets[answer]));
  } else if (flow.app === 'PING') {
    const sent = new Map<number, Packet>();
    const trips: number[] = [];
    for (const p of packets) {
      const echo = p.info?.icmp;
      if (echo?.echo === 'request') sent.set(echo.seq!, p);
      else if (echo?.echo === 'reply' && sent.has(echo.seq!)) trips.push(ms(sent.get(echo.seq!)!, p));
    }
    if (trips.length) add('rtt', trips.reduce((a, b) => a + b, 0) / trips.length, { count: trips.length, min: Math.min(...trips), max: Math.max(...trips) });
  } else if (flow.app === 'ARP') {
    const ask = first((p) => p.info?.arp === 'request');
    const answer = ask < 0 ? -1 : first((p) => p.info?.arp === 'reply', ask);
    if (answer >= 0) add('arp', ms(packets[ask], packets[answer]));
  } else if (flow.app === 'DHCP') {
    const done = first((p) => p.info?.dhcp === 5);
    if (done > 0) add('dhcp', ms(packets[0], packets[done]));
  }

  let slowest: Phase | undefined;
  for (const phase of phases) if (!slowest || phase.ms > slowest.ms) slowest = phase;
  return { phases, totalMs: (flow.lastTs - flow.firstTs) * 1000, slowest: phases.length > 1 ? slowest : undefined };
}
