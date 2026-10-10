import type { Endpoint, Flow } from './types.ts';

/** 대화 종류별 한 줄 소개 */
const GUIDE: Record<string, string> = {
  DNS: '사람이 읽는 이름(예: naver.com)을 컴퓨터가 쓰는 IP 주소로 바꾸는 과정입니다. 웹사이트에 접속할 때 가장 먼저 일어납니다.',
  mDNS: '같은 네트워크 안의 기기들이 DNS 서버 없이 서로 이름을 찾는 과정입니다.',
  LLMNR: '같은 네트워크 안의 윈도우 기기들이 서로 이름을 찾는 과정입니다.',
  HTTP: '암호화되지 않은 웹 통신입니다. 주고받는 내용이 그대로 보입니다.',
  HTTPS: '암호화된 웹 통신입니다. 어디에 접속했는지는 보이지만 주고받는 내용은 볼 수 없습니다.',
  TLS: '암호화된 통신입니다. 누구와 통신하는지는 보이지만 내용은 볼 수 없습니다.',
  QUIC: 'UDP 위에서 동작하는 최신 암호화 웹 통신(HTTP/3)입니다. 연결 과정까지 대부분 암호화되어 있습니다.',
  ARP: 'IP 주소만 아는 상태에서 그 장비의 MAC 주소를 물어보는 과정입니다. 같은 네트워크 안에서 통신하기 전에 꼭 필요합니다.',
  PING: '상대가 살아 있는지, 응답이 얼마나 걸리는지 확인하는 신호입니다.',
  ICMP: '네트워크 상태나 오류를 알려 주는 쪽지입니다.',
  ICMPv6: 'IPv6 네트워크에서 이웃 찾기와 상태 알림에 쓰이는 쪽지입니다.',
  DHCP: '네트워크에 접속한 기기가 IP 주소를 자동으로 받아 오는 과정입니다. 찾기 → 제안 → 요청 → 확정 순서로 진행됩니다.',
  TCP: '연결을 맺고 데이터를 순서대로 확실하게 주고받는 통신입니다.',
  UDP: '연결 없이 데이터를 바로 던지는 통신입니다. 빠르지만 도착 확인이 없습니다.',
};

export const flowGuide = (flow: Flow) => GUIDE[flow.app] ?? (flow.tcp ? GUIDE.TCP : flow.key.startsWith('udp') ? GUIDE.UDP : '두 장비가 주고받은 패킷 묶음입니다.');

export function endpointName(ep: Endpoint, names: Map<string, string>): string {
  return ep.label ?? names.get(ep.addr) ?? ep.addr;
}

export function endpointAddr(ep: Endpoint): string {
  if (!ep.addr) return '';
  if (ep.port === undefined) return ep.addr;
  return ep.addr.includes(':') ? `[${ep.addr}]:${ep.port}` : `${ep.addr}:${ep.port}`;
}

export function flowTitle(flow: Flow, names: Map<string, string>): string {
  const peer = flow.host ?? names.get(flow.b.addr) ?? flow.b.addr;
  switch (flow.app) {
    case 'DNS':
    case 'mDNS':
    case 'LLMNR':
      return `이름 찾기: ${flow.host ?? '?'}`;
    case 'HTTP':
      return `웹 페이지 요청: ${peer}`;
    case 'HTTPS':
    case 'QUIC':
      return `암호화된 웹 통신: ${peer}`;
    case 'ARP':
      return `MAC 주소 찾기: ${flow.b.addr}`;
    case 'PING':
      return `핑: ${peer}`;
    case 'DHCP':
      return 'IP 주소 자동 할당';
    default:
      return `${flow.app} 통신: ${peer}${flow.b.port === undefined ? '' : ` (포트 ${flow.b.port})`}`;
  }
}

export interface StatusChip {
  label: string;
  tone: 'ok' | 'warn' | 'info';
}

/** TCP 대화가 지금 어디까지 진행됐는지 */
export function flowStatus(flow: Flow): StatusChip[] {
  const s = flow.tcp;
  if (!s) return [];
  const chips: StatusChip[] = [];
  if (s.established && s.syn) chips.push({ label: '연결 수립 완료', tone: 'ok' });
  else if (s.syn) chips.push({ label: '연결 시도 중 (응답 없음)', tone: 'warn' });
  else chips.push({ label: '캡처 시작 전부터 연결되어 있었음', tone: 'info' });
  chips.push({ label: `주고받은 데이터 ${s.dataBytes.toLocaleString()}바이트`, tone: 'info' });
  if (s.retransmits) chips.push({ label: `재전송 ${s.retransmits}회`, tone: 'warn' });
  if (s.rst) chips.push({ label: '강제 종료됨', tone: 'warn' });
  else if (s.fin.a && s.fin.b) chips.push({ label: '정상 종료', tone: 'ok' });
  else if (s.fin.a || s.fin.b) chips.push({ label: '종료하는 중', tone: 'info' });
  else chips.push({ label: '연결 유지 중', tone: 'info' });
  return chips;
}

export const STAGE_TITLES = {
  open: '연결 맺기 (3-way handshake)',
  data: '데이터 주고받기',
  close: '연결 끊기',
} as const;
