import type { Messages } from '../i18n/index.ts';
import type { Endpoint, Flow } from './types.ts';

/** 대화 종류별 한 줄 소개 */
export function flowGuide(flow: Flow, L: Messages): string {
  const guide = L.flow.guide;
  return guide[flow.app] ?? (flow.tcp ? guide.TCP : flow.key.startsWith('udp') ? guide.UDP : L.flow.guideOther);
}

export function endpointName(ep: Endpoint, names: Map<string, string>): string {
  return ep.label ?? ep.name ?? names.get(ep.addr) ?? ep.addr;
}

export function endpointAddr(ep: Endpoint): string {
  if (!ep.addr) return '';
  if (ep.port === undefined) return ep.addr;
  return ep.addr.includes(':') ? `[${ep.addr}]:${ep.port}` : `${ep.addr}:${ep.port}`;
}

export function flowTitle(flow: Flow, names: Map<string, string>, L: Messages): string {
  const m = L.flow;
  const peer = flow.host ?? flow.b.name ?? names.get(flow.b.addr) ?? flow.b.addr;
  switch (flow.app) {
    case 'DNS':
    case 'mDNS':
    case 'LLMNR':
      return m.lookup(flow.host ?? '?');
    case 'HTTP':
      return m.web(peer);
    case 'HTTPS':
    case 'QUIC':
      return m.secureWeb(peer);
    case 'ARP':
      return m.arp(flow.b.addr);
    case 'PING':
      return m.ping(peer);
    case 'DHCP':
      return m.dhcp;
    default:
      return m.other(flow.app, peer, flow.b.port);
  }
}

export interface StatusChip {
  label: string;
  tone: 'ok' | 'warn' | 'info';
}

/** TCP 대화가 지금 어디까지 진행됐는지 */
export function flowStatus(flow: Flow, L: Messages): StatusChip[] {
  const m = L.flow;
  const s = flow.tcp;
  if (!s) return [];
  const chips: StatusChip[] = [];
  if (s.established && s.syn) chips.push({ label: m.established, tone: 'ok' });
  else if (s.syn) chips.push({ label: m.trying, tone: 'warn' });
  else chips.push({ label: m.preexisting, tone: 'info' });
  chips.push({ label: m.dataBytes(s.dataBytes.toLocaleString(L.tag)), tone: 'info' });
  if (s.retransmits) chips.push({ label: m.retransmits(s.retransmits), tone: 'warn' });
  if (s.rst) chips.push({ label: m.reset, tone: 'warn' });
  else if (s.fin.a && s.fin.b) chips.push({ label: m.closed, tone: 'ok' });
  else if (s.fin.a || s.fin.b) chips.push({ label: m.closing, tone: 'info' });
  else chips.push({ label: m.open, tone: 'info' });
  return chips;
}
