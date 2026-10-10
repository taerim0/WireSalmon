import type { Messages } from '../i18n/index.ts';
import { endpointName } from './describe.ts';
import { timing } from './timing.ts';
import type { Flow } from './types.ts';

export type Tone = 'ok' | 'info' | 'warn' | 'bad';

/** 대화 하나에서 찾아낸 사실 하나: 무슨 일인지(title)와 흔한 원인(detail) */
export interface Finding {
  tone: Tone;
  title: string;
  detail: string;
}

const SYN = 0x02;
const ACK = 0x10;
const FIN = 0x01;
const RST = 0x04;

// 답을 이만큼 기다렸는데도 없으면 "응답 없음"으로 본다 (초)
const WAIT_TCP = 1;
const WAIT_DNS = 2;
const WAIT_PING = 2;
const WAIT_ARP = 1;
const WAIT_DHCP = 3;

/**
 * 대화를 살펴보고 문제나 특이점을 쉬운 말로 풀어 준다.
 * now는 캡처의 마지막 시각으로, 방금 보낸 요청을 "응답 없음"으로 오해하지 않기 위해 쓴다.
 */
export function diagnose(flow: Flow, names: Map<string, string>, L: Messages, now: number): Finding[] {
  const m = L.diag;
  const out: Finding[] = [];
  const add = (tone: Tone, [title, detail]: [string, string]) => out.push({ tone, title, detail });
  const packets = flow.packets;
  /** 눈에 띄게 느린 구간은 문제로 알린다. 이 대화가 아닌 앞선 DNS 조회는 그 대화에서 알린다. */
  const addSlow = () => {
    for (const phase of timing(flow).phases) {
      if (phase.verySlow && phase.kind !== 'dns') add('warn', [m.slow(L.timing.labels[phase.kind], L.timing.duration(phase.ms)), L.timing.slowHint[phase.kind] ?? '']);
    }
  };

  /** DNS 질문과 답을 살핀다. UDP든 TCP든 내용은 같다. */
  const dnsFindings = () => {
    const queries = packets.filter((p) => p.info?.dns && !p.info.dns.response);
    const answers = packets.filter((p) => p.info?.dns?.response);
    if (answers.length === 0) {
      if (queries.length && now - queries[0].ts > WAIT_DNS) add('bad', m.dnsNoAnswer(queries.length));
      return;
    }
    const codes = answers.map((p) => p.info!.dns!.rcode);
    const other = codes.find((code) => code !== 0);
    if (codes.includes(3)) add('warn', m.nxdomain(flow.host ?? '?'));
    else if (codes.includes(2)) add('bad', m.servfail);
    else if (codes.includes(5)) add('warn', m.dnsRefused);
    else if (other) add('warn', m.dnsError(other));
    else if (answers.every((p) => p.info!.dns!.answers === 0)) add('info', m.dnsNoData);
    else add('ok', m.dnsOk);
  };

  if (flow.tcp) {
    const s = flow.tcp;
    const syns = packets.filter((p) => p.fromA && p.tcp && (p.tcp.flags & (SYN | ACK)) === SYN);
    const rstAt = packets.findIndex((p) => p.tcp && p.tcp.flags & RST);
    if (s.syn && !s.synAck) {
      if (rstAt >= 0 && !packets[rstAt].fromA) add('bad', m.refused(flow.b.port ?? 0));
      else if (syns.length > 1 || now - syns[0].ts > WAIT_TCP) add('bad', m.noAnswer(syns.length));
      else add('info', m.connecting);
    } else if (rstAt >= 0) {
      const closedFirst = packets.slice(0, rstAt).some((p) => p.tcp && p.tcp.flags & FIN);
      const who = endpointName(packets[rstAt].fromA ? flow.a : flow.b, names);
      if (closedFirst) add('info', m.resetAfterClose);
      // 접속한 쪽 프로그램이 볼일을 마치고 연결을 바로 닫는 일은 흔하다
      else if (packets[rstAt].fromA && s.dataBytes > 0) add('info', m.closedByReset(who));
      else add('warn', m.aborted(who));
    }
    if (s.retransmits) add(s.retransmits >= 3 ? 'warn' : 'info', m.retransmits(s.retransmits));

    const alert = packets.find((p) => p.info?.tlsAlert?.fatal)?.info?.tlsAlert;
    if (alert) add('bad', m.tlsFailed(m.tlsAlerts[alert.code] ?? String(alert.code)));

    const seen = new Set<number>();
    for (const p of packets) {
      const status = p.info?.http?.status;
      if (status === undefined || status < 400 || seen.has(status) || seen.size >= 3) continue;
      seen.add(status);
      const meaning = L.http.status[String(status)] ?? p.info?.http?.reason ?? '';
      add(status >= 500 ? 'bad' : 'warn', status >= 500 ? m.httpServerError(status, meaning) : m.httpClientError(status, meaning));
    }
    if (flow.app === 'DNS') dnsFindings();
    addSlow();
    if (s.syn && s.established && !out.some((f) => f.tone === 'bad' || f.tone === 'warn')) add('ok', m.connected);
    return out;
  }

  if (flow.app === 'DNS') {
    dnsFindings();
    addSlow();
    return out;
  }

  if (flow.app === 'PING') {
    const replied = new Set(packets.filter((p) => p.info?.icmp?.echo === 'reply').map((p) => p.info!.icmp!.seq));
    const requests = packets.filter((p) => p.info?.icmp?.echo === 'request');
    const lost = requests.filter((p) => !replied.has(p.info!.icmp!.seq) && now - p.ts > WAIT_PING).length;
    if (requests.length === 0) return out;
    if (lost === requests.length) add('bad', m.pingNoReply(lost));
    else if (lost) add('warn', m.pingLoss(lost, requests.length));
    else if (replied.size) add('ok', m.pingOk(replied.size));
    addSlow();
    return out;
  }

  if (flow.app === 'ICMP' || flow.app === 'ICMPv6') {
    const types = new Set(packets.map((p) => (p.info?.icmp ? `${p.info.icmp.v6 ? 6 : 4}:${p.info.icmp.type}` : '')));
    const unreachable = packets.filter((p) => p.info?.icmp && p.info.icmp.type === (p.info.icmp.v6 ? 1 : 3));
    // "그 포트에는 아무도 없다"는 목적지 컴퓨터가 직접 보내는 답이라 경로 문제와 구별한다
    const portOnly = unreachable.every((p) => p.info!.icmp!.code === (p.info!.icmp!.v6 ? 4 : 3));
    if (unreachable.length) add(portOnly ? 'info' : 'warn', portOnly ? m.portUnreachable : m.unreachable);
    if (types.has('4:11') || types.has('6:3')) add('info', m.ttlExpired);
    return out;
  }

  if (flow.app === 'ARP') {
    // 자기 주소 알림과 주소 충돌 확인은 답이 없는 것이 정상이라 뺀다
    const asks = packets.filter((p) => p.info?.arp === 'request' && p.src !== p.dst && p.src !== '0.0.0.0');
    const answered = packets.some((p) => p.info?.arp === 'reply');
    if (asks.length && !answered && now - asks[0].ts > WAIT_ARP) add('info', m.arpNoReply(asks[0].dst));
    else if (answered) add('ok', m.arpOk);
    return out;
  }

  if (flow.app === 'DHCP') {
    const types = new Set(packets.map((p) => p.info?.dhcp));
    if (types.has(6)) add('bad', m.dhcpNak);
    else if (types.has(5)) add('ok', m.dhcpOk);
    else if (types.has(1) && !types.has(2) && now - packets[0].ts > WAIT_DHCP) add('info', m.dhcpNoOffer);
  }
  return out;
}

const cache = new WeakMap<Flow, { size: number; L: Messages; second: number; findings: Finding[] }>();

/** 목록을 그릴 때마다 모든 대화를 다시 훑지 않도록 결과를 기억해 둔다 */
export function findings(flow: Flow, names: Map<string, string>, L: Messages, now: number): Finding[] {
  const second = Math.floor(now);
  const hit = cache.get(flow);
  if (hit && hit.size === flow.packets.length && hit.L === L && hit.second === second) return hit.findings;
  const result = diagnose(flow, names, L, now);
  cache.set(flow, { size: flow.packets.length, L, second, findings: result });
  return result;
}

/** 대화에 사용자가 봐야 할 문제가 있으면 그 심각도를 돌려준다 */
export function problemOf(list: Finding[]): 'bad' | 'warn' | null {
  if (list.some((f) => f.tone === 'bad')) return 'bad';
  return list.some((f) => f.tone === 'warn') ? 'warn' : null;
}
