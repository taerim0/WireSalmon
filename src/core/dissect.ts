import { hex, ipv4, ipv6, mac, printable, u16, u32, utf8 } from './bytes.ts';
import type { RawPacket } from './reader.ts';
import type { Field, Packet } from './types.ts';

const f = (label: string, value: string | number, help?: string): Field => ({ label, value: String(value), help });

function need(d: Uint8Array, o: number, n: number) {
  if (o + n > d.length) throw new Error('truncated');
}

const pairKey = (kind: string, a: string, b: string) => `${kind}|${[a, b].sort().join('|')}`;

/** 잘 알려진 포트: [이름, 한 줄 설명] */
export const KNOWN_PORTS: Record<number, [string, string]> = {
  20: ['FTP', '파일 전송 (데이터)'],
  21: ['FTP', '파일 전송 (명령)'],
  22: ['SSH', '암호화된 원격 접속'],
  23: ['Telnet', '암호화되지 않은 원격 접속'],
  25: ['SMTP', '메일 보내기'],
  53: ['DNS', '이름을 IP 주소로 바꾸기'],
  67: ['DHCP', 'IP 주소 자동 할당'],
  68: ['DHCP', 'IP 주소 자동 할당'],
  80: ['HTTP', '암호화되지 않은 웹'],
  110: ['POP3', '메일 받기'],
  123: ['NTP', '시계 맞추기'],
  137: ['NBNS', '윈도우 컴퓨터 이름 찾기'],
  138: ['NetBIOS', '윈도우 네트워크 알림'],
  143: ['IMAP', '메일 받기'],
  443: ['HTTPS', '암호화된 웹'],
  445: ['SMB', '윈도우 파일 공유'],
  587: ['SMTP', '메일 보내기'],
  993: ['IMAPS', '암호화된 메일 받기'],
  1900: ['SSDP', '주변 기기 찾기'],
  3306: ['MySQL', '데이터베이스'],
  3389: ['RDP', '윈도우 원격 데스크톱'],
  5353: ['mDNS', '같은 네트워크 안에서 이름 찾기'],
  5355: ['LLMNR', '같은 네트워크 안에서 이름 찾기'],
  5432: ['PostgreSQL', '데이터베이스'],
  6379: ['Redis', '데이터 저장소'],
  8080: ['HTTP', '웹 (대체 포트)'],
};

const portText = (port: number) => (KNOWN_PORTS[port] ? `${port} (${KNOWN_PORTS[port][0]} · ${KNOWN_PORTS[port][1]})` : String(port));

const PORT_HELP =
  '포트는 한 컴퓨터 안에서 어떤 프로그램에게 전달할지 정하는 번호입니다. 아파트 주소가 IP라면 포트는 호수입니다. 서버는 정해진 번호(웹은 80, 443)를 쓰고, 접속하는 쪽은 임시 번호를 받습니다.';

export function dissect(raw: RawPacket, no: number): Packet {
  const p: Packet = {
    no,
    ts: raw.ts,
    origLen: raw.origLen,
    data: raw.data,
    layers: [],
    src: '?',
    dst: '?',
    proto: '알 수 없음',
    summary: '해석할 수 없는 패킷',
    flowKey: `unknown|${raw.linkType}`,
  };
  const d = raw.data;
  try {
    switch (raw.linkType) {
      case 1:
        ethernet(p, d, 0);
        break;
      case 101:
      case 228:
      case 229:
        network(p, d, 0, d[0] >> 4 === 6 ? 0x86dd : 0x0800);
        break;
      case 0: {
        // 루프백: 앞 4바이트가 주소 체계 번호
        need(d, 0, 4);
        const family = d[0] || d[3];
        network(p, d, 4, family === 2 ? 0x0800 : 0x86dd);
        break;
      }
      case 113:
        need(d, 0, 16);
        network(p, d, 16, u16(d, 14));
        break;
      case 276:
        need(d, 0, 20);
        network(p, d, 20, u16(d, 0));
        break;
      default:
        p.summary = `지원하지 않는 연결 방식 (링크 타입 ${raw.linkType})`;
    }
  } catch {
    p.truncated = true;
    if (p.layers.length === 0) p.summary = '패킷이 잘려 있어 해석할 수 없습니다';
  }
  return p;
}

function network(p: Packet, d: Uint8Array, o: number, etherType: number) {
  if (etherType === 0x0800) ip4(p, d, o);
  else if (etherType === 0x86dd) ip6(p, d, o);
  else if (etherType === 0x0806) arp(p, d, o);
}

const ETHER_NAMES: Record<number, string> = {
  0x0800: 'IPv4',
  0x86dd: 'IPv6',
  0x0806: 'ARP',
  0x8100: 'VLAN',
  0x88cc: 'LLDP',
  0x888e: 'EAPOL (와이파이 인증)',
};

function ethernet(p: Packet, d: Uint8Array, o: number) {
  need(d, o, 14);
  const dst = mac(d, o);
  const src = mac(d, o + 6);
  let type = u16(d, o + 12);
  let off = o + 14;
  let vlan: number | undefined;
  while (type === 0x8100 || type === 0x88a8) {
    need(d, off, 4);
    vlan = u16(d, off) & 0xfff;
    type = u16(d, off + 2);
    off += 4;
  }
  const typeName = type < 1536 ? 'IEEE 802.3 (장비끼리 쓰는 관리용 프레임)' : (ETHER_NAMES[type] ?? `0x${hex(type, 4)}`);
  const broadcast = dst === 'ff:ff:ff:ff:ff:ff';
  p.src = src;
  p.dst = dst;
  p.proto = '이더넷';
  p.summary = `이더넷 프레임 (${typeName})`;
  p.flowKey = `${pairKey('l2', src, dst)}|${type}`;
  p.layers.push({
    id: 'eth',
    name: '이더넷',
    osi: '2계층 · 데이터 링크',
    role: '같은 네트워크 안에서 바로 옆 장비(예: 공유기)까지 전달하는 가장 바깥 봉투입니다.',
    start: o,
    end: off,
    fields: [
      f('받는 장비 (MAC)', broadcast ? `${dst} — 같은 네트워크의 모두에게` : dst, 'MAC 주소는 랜카드마다 붙어 있는 고유 번호입니다. ff:ff:ff:ff:ff:ff는 "모두에게 보냄(브로드캐스트)"이라는 뜻입니다.'),
      f('보낸 장비 (MAC)', src, '이 프레임을 내보낸 랜카드의 번호입니다. 공유기를 지날 때마다 MAC 주소는 바뀌지만 IP 주소는 그대로입니다.'),
      ...(vlan === undefined ? [] : [f('VLAN 번호', vlan, '하나의 스위치를 여러 개의 논리적 네트워크로 나눌 때 붙이는 번호입니다.')]),
      f('안에 든 것 (EtherType)', typeName, '이 봉투 안에 어떤 프로토콜이 들어 있는지 알려 주는 번호입니다.'),
    ],
  });
  network(p, d, off, type);
}

function arp(p: Packet, d: Uint8Array, o: number) {
  need(d, o, 28);
  const op = u16(d, o + 6);
  const senderMac = mac(d, o + 8);
  const senderIp = ipv4(d, o + 14);
  const targetMac = mac(d, o + 18);
  const targetIp = ipv4(d, o + 24);
  p.src = senderIp;
  p.dst = targetIp;
  p.proto = 'ARP';
  p.appLabel = 'ARP';
  p.flowKey = pairKey('arp', senderIp, targetIp);
  if (senderIp === targetIp) p.summary = `"${senderIp}는 제 주소입니다" — 모두에게 알림`;
  else if (op === 1) p.summary = `"${targetIp} 쓰는 분 누구세요? ${senderIp}에게 알려 주세요"`;
  else p.summary = `"${senderIp}는 저예요. 제 MAC 주소는 ${senderMac}입니다"`;
  p.layers.push({
    id: 'arp',
    name: 'ARP',
    osi: '2~3계층 사이',
    role: 'IP 주소만 알고 있을 때 그 장비의 MAC 주소를 알아내는 과정입니다. 같은 네트워크 안에서 통신하려면 MAC 주소가 꼭 필요합니다.',
    start: o,
    end: o + 28,
    fields: [
      f('종류', op === 1 ? '질문 (Request)' : '답변 (Reply)', '질문은 모두에게 외치고(브로드캐스트), 답변은 질문한 장비에게만 보냅니다.'),
      f('보낸 쪽 IP', senderIp),
      f('보낸 쪽 MAC', senderMac),
      f('찾는 IP', targetIp),
      f('찾는 MAC', op === 1 ? '아직 모름 (00:00:00:00:00:00)' : targetMac),
    ],
  });
}

const IP_PROTO: Record<number, string> = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6 터널', 47: 'GRE', 50: 'ESP (IPsec)', 58: 'ICMPv6' };

const TTL_HELP =
  '공유기(라우터)를 하나 지날 때마다 1씩 줄어들고, 0이 되면 버려집니다. 패킷이 길을 잃고 영원히 떠도는 것을 막는 장치입니다. 보통 64, 128, 255에서 시작합니다.';

function ip4(p: Packet, d: Uint8Array, o: number) {
  need(d, o, 20);
  const ihl = (d[o] & 15) * 4;
  const total = u16(d, o + 2);
  const flagsFrag = u16(d, o + 6);
  const ttl = d[o + 8];
  const proto = d[o + 9];
  const src = ipv4(d, o + 12);
  const dst = ipv4(d, o + 16);
  const end = total ? Math.min(d.length, o + total) : d.length;
  const fragOffset = (flagsFrag & 0x1fff) * 8;
  const moreFragments = (flagsFrag & 0x2000) !== 0;
  p.src = src;
  p.dst = dst;
  p.proto = 'IPv4';
  p.summary = `IP 패킷 (${IP_PROTO[proto] ?? `프로토콜 ${proto}`})`;
  p.flowKey = `${pairKey('ip', src, dst)}|${proto}`;
  p.layers.push({
    id: 'ipv4',
    name: 'IPv4',
    osi: '3계층 · 네트워크',
    role: '출발지에서 목적지까지, 여러 네트워크를 건너 길을 찾아가게 해 주는 봉투입니다. 택배 송장의 보내는 주소·받는 주소에 해당합니다.',
    start: o,
    end: o + ihl,
    fields: [
      f('보낸 곳 (IP)', src, '인터넷에서 장비를 구분하는 주소입니다. 192.168.x.x, 10.x.x.x, 172.16~31.x.x는 집이나 회사 안에서만 쓰는 사설 주소입니다.'),
      f('받는 곳 (IP)', dst),
      f('남은 수명 (TTL)', ttl, TTL_HELP),
      f('안에 든 것 (Protocol)', IP_PROTO[proto] ?? proto, '이 IP 패킷 안에 TCP가 들었는지 UDP가 들었는지 알려 줍니다.'),
      f('전체 길이', `${total}바이트`),
      f(
        '쪼개짐 (Fragment)',
        fragOffset || moreFragments ? `쪼개진 조각 (위치 ${fragOffset}${moreFragments ? ', 뒤에 더 있음' : ', 마지막 조각'})` : flagsFrag & 0x4000 ? '쪼개지 않음 (DF)' : '쪼개지지 않음',
        '패킷이 지나가는 길의 최대 크기(MTU, 보통 1500바이트)보다 크면 여러 조각으로 나뉩니다. DF는 "쪼개지 마세요"라는 표시입니다.',
      ),
      f('식별 번호 (ID)', u16(d, o + 4), '쪼개진 조각들을 다시 합칠 때 같은 패킷인지 알아보는 번호입니다.'),
    ],
  });
  if (fragOffset > 0) {
    p.summary = '쪼개진 IP 패킷의 뒷부분 조각';
    return;
  }
  transport(p, d, o + ihl, end, proto);
}

function ip6(p: Packet, d: Uint8Array, o: number) {
  need(d, o, 40);
  const payloadLen = u16(d, o + 4);
  let next = d[o + 6];
  const hop = d[o + 7];
  const src = ipv6(d, o + 8);
  const dst = ipv6(d, o + 24);
  const end = payloadLen ? Math.min(d.length, o + 40 + payloadLen) : d.length;
  let off = o + 40;
  // 확장 헤더 건너뛰기
  while (next === 0 || next === 43 || next === 60 || next === 44) {
    need(d, off, 8);
    const len = next === 44 ? 8 : (d[off + 1] + 1) * 8;
    next = d[off];
    off += len;
  }
  p.src = src;
  p.dst = dst;
  p.proto = 'IPv6';
  p.summary = `IPv6 패킷 (${IP_PROTO[next] ?? `프로토콜 ${next}`})`;
  p.flowKey = `${pairKey('ip', src, dst)}|${next}`;
  p.layers.push({
    id: 'ipv6',
    name: 'IPv6',
    osi: '3계층 · 네트워크',
    role: 'IPv4 주소가 부족해져서 만든 새 주소 체계입니다. 역할은 IPv4와 같고 주소가 훨씬 깁니다.',
    start: o,
    end: off,
    fields: [
      f('보낸 곳 (IP)', src, 'fe80::으로 시작하면 같은 네트워크 안에서만 쓰는 주소, ff02::로 시작하면 여러 장비에게 동시에 보내는 주소입니다.'),
      f('받는 곳 (IP)', dst),
      f('남은 수명 (Hop Limit)', hop, TTL_HELP),
      f('안에 든 것 (Next Header)', IP_PROTO[next] ?? next),
      f('내용 길이', `${payloadLen}바이트`),
    ],
  });
  transport(p, d, off, end, next);
}

function transport(p: Packet, d: Uint8Array, o: number, end: number, proto: number) {
  if (proto === 6) tcp(p, d, o, end);
  else if (proto === 17) udp(p, d, o, end);
  else if (proto === 1) icmp(p, d, o, end, false);
  else if (proto === 58) icmp(p, d, o, end, true);
}

const ICMP4: Record<number, string> = {
  0: '핑 응답 — "네, 살아 있어요"',
  3: '목적지에 도달할 수 없음',
  5: '다른 길로 가라는 안내 (Redirect)',
  8: '핑 요청 — "거기 살아 있나요?"',
  11: '수명(TTL)이 다해서 버려짐',
};
const ICMP6: Record<number, string> = {
  1: '목적지에 도달할 수 없음',
  2: '패킷이 너무 큼',
  3: '수명이 다해서 버려짐',
  128: '핑 요청 — "거기 살아 있나요?"',
  129: '핑 응답 — "네, 살아 있어요"',
  133: '"이 네트워크에 공유기 있나요?" (Router Solicitation)',
  134: '"제가 공유기입니다" (Router Advertisement)',
  135: '"이 IP 쓰는 분 누구세요?" (IPv6의 ARP 질문)',
  136: '"그 IP는 저예요" (IPv6의 ARP 답변)',
  143: '멀티캐스트 그룹 가입 알림',
};

function icmp(p: Packet, d: Uint8Array, o: number, end: number, v6: boolean) {
  need(d, o, 8);
  const type = d[o];
  const code = d[o + 1];
  const isEcho = v6 ? type === 128 || type === 129 : type === 0 || type === 8;
  const meaning = (v6 ? ICMP6 : ICMP4)[type] ?? `종류 ${type}`;
  p.proto = v6 ? 'ICMPv6' : 'ICMP';
  p.appLabel = isEcho ? 'PING' : p.proto;
  p.summary = meaning;
  p.flowKey = pairKey(v6 ? 'icmp6' : 'icmp', p.src, p.dst);
  p.layers.push({
    id: 'icmp',
    name: p.proto,
    osi: '3계층 · 네트워크',
    role: '데이터를 나르는 대신 네트워크 상태를 알려 주는 쪽지입니다. ping 명령과 오류 알림에 쓰입니다.',
    start: o,
    end,
    fields: [
      f('종류 (Type)', `${type} — ${meaning}`),
      f('세부 코드 (Code)', code),
      ...(isEcho
        ? [
            f('식별 번호', u16(d, o + 4), '어떤 ping 프로그램이 보낸 것인지 구분하는 번호입니다.'),
            f('순서 번호', u16(d, o + 6), '몇 번째 핑인지 나타냅니다. 요청과 응답의 번호가 같으면 한 쌍입니다.'),
          ]
        : []),
    ],
  });
}

const TCP_FLAGS: [number, string][] = [
  [0x02, 'SYN'],
  [0x10, 'ACK'],
  [0x08, 'PSH'],
  [0x01, 'FIN'],
  [0x04, 'RST'],
  [0x20, 'URG'],
];

function tcp(p: Packet, d: Uint8Array, o: number, end: number) {
  need(d, o, 20);
  const sp = u16(d, o);
  const dp = u16(d, o + 2);
  const seq = u32(d, o + 4);
  const ack = u32(d, o + 8);
  const headerEnd = Math.min(o + Math.max((d[o + 12] >> 4) * 4, 20), end);
  const flags = d[o + 13];
  const payload = d.subarray(headerEnd, end);
  const flagNames = TCP_FLAGS.filter(([bit]) => flags & bit).map(([, name]) => name);
  p.srcPort = sp;
  p.dstPort = dp;
  p.proto = 'TCP';
  p.tcp = { seq, ack, flags, payloadLen: payload.length };
  p.flowKey = pairKey('tcp', `${p.src}#${sp}`, `${p.dst}#${dp}`);
  p.summary = payload.length ? `데이터 ${payload.length}바이트 전송` : `TCP 제어 신호 (${flagNames.join(', ')})`;
  p.layers.push({
    id: 'tcp',
    name: 'TCP',
    osi: '4계층 · 전송',
    role: '먼저 연결을 맺고, 순서대로 빠짐없이 도착했는지 확인하며 보내는 방식입니다. 등기 우편처럼 느리지만 확실합니다.',
    start: o,
    end: headerEnd,
    fields: [
      f('보낸 포트', portText(sp), PORT_HELP),
      f('받는 포트', portText(dp)),
      f(
        '신호 (Flags)',
        flagNames.join(' + ') || '없음',
        'SYN = 연결 시작, ACK = 잘 받았다는 확인, PSH = 모으지 말고 바로 전달, FIN = 정상 종료, RST = 강제 종료.',
      ),
      f('순서 번호 (Seq)', seq, '내가 보내는 데이터가 전체 중 몇 번째 바이트부터인지 나타냅니다. 받는 쪽은 이 번호로 순서를 맞추고 빠진 부분을 찾습니다.'),
      f('확인 번호 (Ack)', flags & 0x10 ? ack : '없음', '"여기까지 잘 받았으니 다음엔 이 번호부터 보내 주세요"라는 뜻입니다.'),
      f('받을 수 있는 양 (Window)', `${u16(d, o + 14)}`, '상대에게 "지금 이만큼 더 받을 수 있어요"라고 알려서 보내는 속도를 조절합니다.'),
      f('담긴 데이터', `${payload.length}바이트`),
    ],
  });
  if (payload.length === 0) return;
  if (http(p, d, headerEnd, end) || tls(p, d, headerEnd, end, sp === 443 || dp === 443)) return;
  dataLayer(p, d, headerEnd, end);
}

function udp(p: Packet, d: Uint8Array, o: number, end: number) {
  need(d, o, 8);
  const sp = u16(d, o);
  const dp = u16(d, o + 2);
  const bodyStart = o + 8;
  p.srcPort = sp;
  p.dstPort = dp;
  p.proto = 'UDP';
  p.flowKey = pairKey('udp', `${p.src}#${sp}`, `${p.dst}#${dp}`);
  p.summary = `데이터 ${Math.max(end - bodyStart, 0)}바이트 전송`;
  p.layers.push({
    id: 'udp',
    name: 'UDP',
    osi: '4계층 · 전송',
    role: '연결을 맺지 않고 그냥 던지는 방식입니다. 도착 확인이 없어 빠르지만 중간에 사라질 수 있습니다. 일반 우편과 비슷합니다.',
    start: o,
    end: bodyStart,
    fields: [f('보낸 포트', portText(sp), PORT_HELP), f('받는 포트', portText(dp)), f('길이', `${u16(d, o + 4)}바이트`)],
  });
  if (end <= bodyStart) return;
  const has = (port: number) => sp === port || dp === port;
  if (has(53)) dns(p, d, bodyStart, end, 'DNS');
  else if (has(5353)) dns(p, d, bodyStart, end, 'mDNS');
  else if (has(5355)) dns(p, d, bodyStart, end, 'LLMNR');
  else if (has(67) || has(68)) dhcp(p, d, bodyStart, end);
  else if (has(443)) {
    p.proto = 'QUIC';
    p.appLabel = 'QUIC';
    p.summary = `암호화된 데이터 ${end - bodyStart}바이트 (QUIC)`;
    dataLayer(p, d, bodyStart, end, 'QUIC는 UDP 위에서 동작하는 최신 암호화 통신 방식입니다. 유튜브나 구글처럼 HTTP/3를 쓰는 사이트에서 볼 수 있습니다.');
  } else dataLayer(p, d, bodyStart, end);
}

function dataLayer(p: Packet, d: Uint8Array, o: number, end: number, role?: string) {
  const known = KNOWN_PORTS[p.dstPort ?? -1] ?? KNOWN_PORTS[p.srcPort ?? -1];
  if (known && !p.appLabel) {
    p.appLabel = known[0];
    p.summary = `${known[1]} 데이터 ${end - o}바이트 (${known[0]})`;
  }
  p.layers.push({
    id: 'data',
    name: p.appLabel ?? '데이터',
    osi: '내용물',
    role: role ?? (known ? `${known[0]}: ${known[1]}에 쓰이는 프로토콜입니다. 아직 자세한 해석은 지원하지 않습니다.` : '봉투 안에 든 실제 내용입니다. 어떤 형식인지 알 수 없어 그대로 보여 드립니다.'),
    start: o,
    end,
    fields: [f('길이', `${end - o}바이트`), f('미리보기', printable(d.subarray(o, end)), '글자로 읽을 수 있는 부분만 보여 줍니다. 점(.)은 글자가 아닌 값입니다.')],
  });
}

const DNS_TYPES: Record<number, [string, string]> = {
  1: ['A', 'IPv4 주소'],
  2: ['NS', '이 도메인을 관리하는 서버'],
  5: ['CNAME', '별명 (다른 이름)'],
  6: ['SOA', '도메인 관리 정보'],
  12: ['PTR', 'IP로 이름 찾기'],
  15: ['MX', '메일 서버'],
  16: ['TXT', '텍스트 메모'],
  28: ['AAAA', 'IPv6 주소'],
  33: ['SRV', '서비스 위치'],
  65: ['HTTPS', 'HTTPS 접속 정보'],
  255: ['ANY', '모든 정보'],
};
const dnsType = (t: number) => (DNS_TYPES[t] ? `${DNS_TYPES[t][0]} (${DNS_TYPES[t][1]})` : `타입 ${t}`);

function dnsName(d: Uint8Array, start: number, base: number, end: number): [string, number] {
  const parts: string[] = [];
  let o = start;
  let after = -1;
  for (let hops = 0; ; ) {
    if (o >= end) throw new Error('truncated');
    const len = d[o];
    if (len === 0) {
      o++;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      // 압축: 앞에 나온 이름을 가리키는 포인터
      if (after < 0) after = o + 2;
      o = base + (((len & 0x3f) << 8) | d[o + 1]);
      if (++hops > 20) throw new Error('loop');
      continue;
    }
    parts.push(utf8(d.subarray(o + 1, o + 1 + len)));
    o += 1 + len;
  }
  return [parts.join('.') || '(루트)', after < 0 ? o : after];
}

function dns(p: Packet, d: Uint8Array, o: number, end: number, label: string) {
  need(d, o, 12);
  const flags = u16(d, o + 2);
  const response = (flags & 0x8000) !== 0;
  const rcode = flags & 15;
  const qd = u16(d, o + 4);
  const an = u16(d, o + 6);
  const fields: Field[] = [
    f('종류', response ? '답변' : '질문'),
    f('질문 번호 (ID)', `0x${hex(u16(d, o), 4)}`, '질문과 답변을 짝짓는 번호입니다. 같은 번호의 질문과 답변이 한 쌍입니다.'),
  ];
  p.proto = label;
  p.appLabel = label;
  let off = o + 12;
  let qname = '';
  let qtype = 1;
  const answers: string[] = [];
  try {
    for (let i = 0; i < qd; i++) {
      const [name, next] = dnsName(d, off, o, end);
      const type = u16(d, next);
      off = next + 4;
      if (i === 0) {
        qname = name;
        qtype = type;
      }
      fields.push(f('질문', `${name} 의 ${dnsType(type)}`, 'A는 IPv4 주소, AAAA는 IPv6 주소를 묻는 질문입니다.'));
    }
    for (let i = 0; i < an; i++) {
      const [name, next] = dnsName(d, off, o, end);
      need(d, next, 10);
      const type = u16(d, next);
      const ttl = u32(d, next + 4);
      const rdLen = u16(d, next + 8);
      const rd = next + 10;
      need(d, rd, rdLen);
      let value: string;
      if (type === 1 && rdLen === 4) value = ipv4(d, rd);
      else if (type === 28 && rdLen === 16) value = ipv6(d, rd);
      else if (type === 5 || type === 12 || type === 2) value = dnsName(d, rd, o, end)[0];
      else value = `(${rdLen}바이트)`;
      if (type === 1 || type === 28) {
        answers.push(value);
        (p.names ??= []).push([value, qname || name]);
      }
      fields.push(f('답변', `${name} → ${value}  [${DNS_TYPES[type]?.[0] ?? type}, ${ttl}초 동안 유효]`, '유효 시간(TTL) 동안은 다시 묻지 않고 이 답을 기억해서 씁니다.'));
      off = rd + rdLen;
    }
  } catch {
    p.truncated = true;
  }
  if (response && rcode) fields.push(f('결과', rcode === 3 ? '그런 이름은 없습니다 (NXDOMAIN)' : `오류 코드 ${rcode}`));
  p.host = qname || undefined;
  if (!response) p.summary = `"${qname}"의 ${DNS_TYPES[qtype]?.[1] ?? '정보'}를 알려 주세요`;
  else if (rcode === 3) p.summary = `"${qname}"이라는 이름은 없습니다`;
  else if (answers.length) p.summary = `"${qname}"의 주소는 ${answers[0]}${answers.length > 1 ? ` 외 ${answers.length - 1}개` : ''}입니다`;
  else p.summary = `"${qname}"에 대한 답변 (${an}건)`;
  p.layers.push({
    id: 'dns',
    name: label,
    osi: '7계층 · 응용',
    role:
      label === 'DNS'
        ? '사람이 읽는 이름(naver.com)을 컴퓨터가 쓰는 IP 주소로 바꿔 주는 인터넷 전화번호부입니다.'
        : '공유기 안쪽 네트워크에서 DNS 서버 없이 서로의 이름을 찾는 방식입니다. 프린터나 스마트 기기를 찾을 때 쓰입니다.',
    start: o,
    end,
    fields,
  });
}

const DHCP_TYPES: Record<number, [string, string]> = {
  1: ['Discover', '"IP 주소 나눠 주는 서버 있나요?"'],
  2: ['Offer', '"이 주소를 쓰세요"'],
  3: ['Request', '"그 주소 제가 쓰겠습니다"'],
  4: ['Decline', '"그 주소는 이미 누가 쓰고 있어요"'],
  5: ['ACK', '"네, 확정입니다"'],
  6: ['NAK', '"그 주소는 드릴 수 없습니다"'],
  7: ['Release', '"주소 반납합니다"'],
  8: ['Inform', '"설정 정보만 알려 주세요"'],
};

function dhcp(p: Packet, d: Uint8Array, o: number, end: number) {
  need(d, o, 240);
  const op = d[o];
  const xid = u32(d, o + 4);
  const yourIp = ipv4(d, o + 16);
  let type = 0;
  const extra: Field[] = [];
  for (let i = o + 240; i + 1 < end; ) {
    const code = d[i];
    if (code === 255) break;
    if (code === 0) {
      i++;
      continue;
    }
    const len = d[i + 1];
    const v = i + 2;
    if (v + len > end) break;
    if (code === 53) type = d[v];
    else if (code === 50) extra.push(f('원하는 주소', ipv4(d, v)));
    else if (code === 1) extra.push(f('서브넷 마스크', ipv4(d, v), '어디까지가 "같은 네트워크"인지 정하는 값입니다.'));
    else if (code === 3) extra.push(f('공유기 주소 (게이트웨이)', ipv4(d, v), '외부 인터넷으로 나갈 때 거쳐 가는 출입구입니다.'));
    else if (code === 6) extra.push(f('DNS 서버', ipv4(d, v)));
    else if (code === 51) extra.push(f('임대 시간', `${u32(d, v)}초`, 'IP 주소는 빌려 쓰는 것이라 이 시간이 지나면 다시 연장해야 합니다.'));
    else if (code === 12) extra.push(f('기기 이름', utf8(d.subarray(v, v + len))));
    i = v + len;
  }
  const [name, meaning] = DHCP_TYPES[type] ?? ['?', 'DHCP 메시지'];
  p.proto = 'DHCP';
  p.appLabel = 'DHCP';
  p.fromClient = op === 1;
  p.flowKey = `dhcp|${xid}`;
  p.summary = type === 2 || type === 5 ? `${meaning} — ${yourIp} (${name})` : `${meaning} (${name})`;
  p.layers.push({
    id: 'dhcp',
    name: 'DHCP',
    osi: '7계층 · 응용',
    role: '와이파이에 접속하면 IP 주소를 자동으로 받아 오는 과정입니다. 찾기 → 제안 → 요청 → 확정 4단계로 이루어집니다.',
    start: o,
    end,
    fields: [
      f('메시지', `${name} — ${meaning}`),
      f('거래 번호', `0x${hex(xid, 8)}`, '한 번의 주소 할당 과정을 묶는 번호입니다.'),
      f('기기 MAC', mac(d, o + 28)),
      ...(yourIp === '0.0.0.0' ? [] : [f('할당된 주소', yourIp)]),
      ...extra,
    ],
  });
}

const HTTP_REQ = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP\/1\.[01]\r?\n/;
const HTTP_RES = /^HTTP\/1\.[01] (\d{3}) ?([^\r\n]*)\r?\n/;
const HTTP_METHODS: Record<string, string> = {
  GET: '가져오기',
  POST: '보내기·제출',
  PUT: '덮어쓰기',
  DELETE: '삭제',
  HEAD: '정보만 확인',
  OPTIONS: '가능한 동작 확인',
  PATCH: '일부 수정',
};
const HTTP_STATUS: Record<string, string> = {
  '200': '성공',
  '201': '만들어짐',
  '204': '성공 (내용 없음)',
  '206': '일부만 전송',
  '301': '주소가 영구히 바뀜',
  '302': '다른 주소로 이동',
  '304': '바뀐 것 없음 (저장해 둔 것을 쓰세요)',
  '400': '잘못된 요청',
  '401': '로그인 필요',
  '403': '접근 금지',
  '404': '찾을 수 없음',
  '429': '요청이 너무 많음',
  '500': '서버 내부 오류',
  '502': '중간 서버 오류',
  '503': '서버 사용 불가',
};
const HTTP_HEADER_HELP: Record<string, string> = {
  host: '접속하려는 사이트 이름입니다. 한 서버가 여러 사이트를 운영할 수 있어서 꼭 필요합니다.',
  'user-agent': '요청을 보낸 프로그램(브라우저) 정보입니다.',
  'content-type': '본문이 어떤 종류의 데이터인지 알려 줍니다 (HTML, 이미지, JSON 등).',
  'content-length': '본문의 크기(바이트)입니다.',
  cookie: '이전에 서버가 준 쿠키를 다시 보내는 것입니다. 로그인 상태 유지에 쓰입니다.',
  'set-cookie': '서버가 브라우저에 저장해 두라고 주는 값입니다.',
  location: '이 주소로 다시 접속하라는 안내입니다.',
  server: '서버 프로그램 정보입니다.',
};

function http(p: Packet, d: Uint8Array, o: number, end: number): boolean {
  // 첫 글자가 대문자 알파벳이 아니면 HTTP일 수 없다
  if (d[o] < 65 || d[o] > 90) return false;
  const text = utf8(d.subarray(o, Math.min(end, o + 8192)));
  const req = HTTP_REQ.exec(text);
  const res = req ? null : HTTP_RES.exec(text);
  if (!req && !res) return false;
  const headEnd = text.search(/\r?\n\r?\n/);
  const lines = (headEnd < 0 ? text : text.slice(0, headEnd)).split(/\r?\n/).slice(1);
  const headers: [string, string][] = [];
  for (const line of lines) {
    const i = line.indexOf(':');
    if (i > 0) headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  const get = (name: string) => headers.find(([k]) => k.toLowerCase() === name)?.[1];
  const fields: Field[] = [];
  p.proto = 'HTTP';
  p.appLabel = 'HTTP';
  if (req) {
    const [, method, path] = req;
    p.host = get('host');
    p.summary = `${method} ${path.length > 60 ? `${path.slice(0, 60)}…` : path} — ${path === '/' ? '첫 페이지 ' : ''}${HTTP_METHODS[method] ?? method} 요청`;
    fields.push(f('요청 방식 (Method)', `${method} — ${HTTP_METHODS[method] ?? ''}`, 'GET은 가져오기, POST는 보내기입니다. 주소창에 주소를 치면 GET 요청이 나갑니다.'));
    fields.push(f('경로', path, '사이트 안에서 원하는 자원의 위치입니다.'));
  } else if (res) {
    const [, status, reason] = res;
    p.summary = `${status} ${reason} — ${HTTP_STATUS[status] ?? `${status[0]}xx 응답`}`;
    fields.push(
      f('상태 코드', `${status} ${reason} — ${HTTP_STATUS[status] ?? ''}`, '2xx는 성공, 3xx는 다른 곳으로 이동, 4xx는 요청한 쪽 잘못, 5xx는 서버 쪽 잘못입니다.'),
    );
  }
  for (const [k, v] of headers) fields.push(f(k, v.length > 200 ? `${v.slice(0, 200)}…` : v, HTTP_HEADER_HELP[k.toLowerCase()]));
  if (headEnd >= 0) {
    const body = text.slice(headEnd).replace(/^\s+/, '');
    if (body) fields.push(f('본문 미리보기', body.length > 300 ? `${body.slice(0, 300)}…` : body, 'HTTP는 암호화하지 않기 때문에 내용이 그대로 보입니다. 그래서 요즘은 대부분 HTTPS를 씁니다.'));
  }
  p.layers.push({
    id: 'http',
    name: 'HTTP',
    osi: '7계층 · 응용',
    role: '웹 브라우저와 웹 서버가 대화하는 규칙입니다. 브라우저가 "이 페이지 주세요"라고 요청하면 서버가 응답합니다. 암호화되지 않아 내용이 그대로 보입니다.',
    start: o,
    end,
    fields,
  });
  return true;
}

const TLS_HANDSHAKE: Record<number, [string, string]> = {
  1: ['Client Hello', '암호화 통신 시작 인사'],
  2: ['Server Hello', '서버의 응답 인사 · 암호화 방식 결정'],
  4: ['New Session Ticket', '다음에 빨리 접속하기 위한 표'],
  8: ['Encrypted Extensions', '추가 설정'],
  11: ['Certificate', '서버 신분증(인증서) 전달'],
  12: ['Server Key Exchange', '서버의 열쇠 재료 전달'],
  13: ['Certificate Request', '클라이언트 인증서 요청'],
  14: ['Server Hello Done', '서버 인사 끝'],
  15: ['Certificate Verify', '인증서 주인 확인'],
  16: ['Client Key Exchange', '클라이언트의 열쇠 재료 전달'],
  20: ['Finished', '준비 완료'],
};
const TLS_RECORDS: Record<number, [string, string]> = {
  20: ['Change Cipher Spec', '"이제부터 암호화합니다"'],
  21: ['Alert', '경고 또는 종료 알림'],
  23: ['Application Data', '암호화된 실제 데이터 (내용은 볼 수 없음)'],
};
const TLS_VERSIONS: Record<number, string> = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };

function tlsServerName(d: Uint8Array, o: number, end: number): string | undefined {
  // Client Hello 본문: 버전(2) 난수(32) 세션ID 암호목록 압축목록 확장목록
  let q = o + 4 + 2 + 32;
  q += 1 + d[q];
  q += 2 + u16(d, q);
  q += 1 + d[q];
  const extEnd = Math.min(end, q + 2 + u16(d, q));
  q += 2;
  while (q + 4 <= extEnd) {
    const type = u16(d, q);
    const len = u16(d, q + 2);
    if (type === 0) {
      const nameLen = u16(d, q + 7);
      if (q + 9 + nameLen <= end) return utf8(d.subarray(q + 9, q + 9 + nameLen));
      return undefined;
    }
    q += 4 + len;
  }
  return undefined;
}

function tls(p: Packet, d: Uint8Array, o: number, end: number, web: boolean): boolean {
  const isRecord = (i: number) => i + 5 <= end && d[i] >= 20 && d[i] <= 23 && d[i + 1] === 3 && d[i + 2] <= 4;
  if (!isRecord(o)) return false;
  const messages: [string, string][] = [];
  let sni: string | undefined;
  let i = o;
  while (isRecord(i) && messages.length < 8) {
    const type = d[i];
    const len = u16(d, i + 3);
    if (type === 22) {
      const known = TLS_HANDSHAKE[d[i + 5]];
      const bodyLen = (d[i + 6] << 16) | u16(d, i + 7);
      if (known && bodyLen + 4 <= len) {
        messages.push(known);
        if (d[i + 5] === 1) sni = tlsServerName(d, i + 5, Math.min(end, i + 5 + len));
      } else messages.push(['Handshake', '암호화된 연결 준비 메시지']);
    } else messages.push(TLS_RECORDS[type]);
    i += 5 + len;
  }
  p.proto = 'TLS';
  p.appLabel = web ? 'HTTPS' : 'TLS';
  p.host = sni;
  p.summary = messages
    .slice(0, 3)
    .map(([name, meaning]) => (name === 'Application Data' ? meaning : `${meaning} (${name})`))
    .join(' + ');
  if (sni) p.summary += ` — 접속하려는 곳: ${sni}`;
  p.layers.push({
    id: 'tls',
    name: 'TLS',
    osi: '5~6계층 · 암호화',
    role: '내용을 암호화해서 중간에서 엿보거나 바꾸지 못하게 하는 보안 봉투입니다. HTTPS의 S가 바로 이것입니다. 처음에 인사(핸드셰이크)로 열쇠를 정한 뒤 암호화된 데이터를 주고받습니다.',
    start: o,
    end,
    fields: [
      f('버전 표시', TLS_VERSIONS[u16(d, o + 1)] ?? '?', 'TLS 1.3도 호환성 때문에 여기에는 1.2 이하로 적습니다.'),
      ...messages.map(([name, meaning]) => f('메시지', `${name} — ${meaning}`)),
      ...(sni
        ? [f('접속하려는 사이트 (SNI)', sni, '암호화가 시작되기 전이라 사이트 이름은 그대로 보입니다. 내용은 못 봐도 "어디에 접속했는지"는 알 수 있는 이유입니다.')]
        : []),
    ],
  });
  return true;
}
