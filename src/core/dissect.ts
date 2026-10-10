import type { Messages } from '../i18n/index.ts';
import { hex, ipv4, ipv6, mac, printable, u16, u32, utf8 } from './bytes.ts';
import type { RawPacket } from './reader.ts';
import type { Field, Packet, PacketInfo } from './types.ts';

const f = (label: string, value: string | number, help?: string): Field => ({ label, value: String(value), help });

function need(d: Uint8Array, o: number, n: number) {
  if (o + n > d.length) throw new Error('truncated');
}

const pairKey = (kind: string, a: string, b: string) => `${kind}|${[a, b].sort().join('|')}`;

/** 잘 알려진 포트의 프로토콜 이름. 하는 일 설명은 언어별 사전(ports)에 있다. */
export const KNOWN_PORTS: Record<number, string> = {
  20: 'FTP',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  137: 'NBNS',
  138: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  587: 'SMTP',
  993: 'IMAPS',
  1900: 'SSDP',
  3306: 'MySQL',
  3389: 'RDP',
  5353: 'mDNS',
  5355: 'LLMNR',
  5432: 'PostgreSQL',
  6379: 'Redis',
  8080: 'HTTP',
};

const ETHER_NAMES: Record<number, string> = { 0x0800: 'IPv4', 0x86dd: 'IPv6', 0x0806: 'ARP', 0x8100: 'VLAN', 0x88cc: 'LLDP' };
const IP_PROTO: Record<number, string> = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP (IPsec)', 58: 'ICMPv6' };
const TCP_FLAGS: [number, string][] = [
  [0x02, 'SYN'],
  [0x10, 'ACK'],
  [0x08, 'PSH'],
  [0x01, 'FIN'],
  [0x04, 'RST'],
  [0x20, 'URG'],
];
const DNS_TYPES: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY' };
const DHCP_TYPES: Record<number, string> = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
const HTTP_REQ = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP\/1\.[01]\r?\n/;
const HTTP_RES = /^HTTP\/1\.[01] (\d{3}) ?([^\r\n]*)\r?\n/;
const TLS_HANDSHAKE: Record<number, string> = {
  1: 'Client Hello',
  2: 'Server Hello',
  4: 'New Session Ticket',
  8: 'Encrypted Extensions',
  11: 'Certificate',
  12: 'Server Key Exchange',
  13: 'Certificate Request',
  14: 'Server Hello Done',
  15: 'Certificate Verify',
  16: 'Client Key Exchange',
  20: 'Finished',
};
const TLS_RECORDS: Record<number, string> = { 20: 'Change Cipher Spec', 21: 'Alert', 23: 'Application Data' };
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

/** 주어진 언어로 패킷을 설명하는 해석기를 만든다 */
export function createDissector(L: Messages) {
  const portText = (port: number) => (KNOWN_PORTS[port] ? `${port} (${KNOWN_PORTS[port]} · ${L.ports[port]})` : String(port));
  const ipProto = (n: number) => (n === 41 ? L.ip.tunnel6 : (IP_PROTO[n] ?? L.ip.protoN(n)));

  function dissect(raw: RawPacket, no: number): Packet {
    const p: Packet = {
      no,
      ts: raw.ts,
      origLen: raw.origLen,
      data: raw.data,
      layers: [],
      src: '?',
      dst: '?',
      proto: L.packet.unknownProto,
      summary: L.packet.unparsable,
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
          p.summary = L.packet.unsupportedLink(raw.linkType);
      }
    } catch {
      p.truncated = true;
      if (p.layers.length === 0) p.summary = L.packet.truncated;
    }
    return p;
  }

  function network(p: Packet, d: Uint8Array, o: number, etherType: number) {
    if (etherType === 0x0800) ip4(p, d, o);
    else if (etherType === 0x86dd) ip6(p, d, o);
    else if (etherType === 0x0806) arp(p, d, o);
  }

  function ethernet(p: Packet, d: Uint8Array, o: number) {
    const m = L.eth;
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
    const typeName = type < 1536 ? m.llc : type === 0x888e ? m.eapol : (ETHER_NAMES[type] ?? `0x${hex(type, 4)}`);
    p.src = src;
    p.dst = dst;
    p.proto = m.name;
    p.summary = m.summary(typeName);
    p.flowKey = `${pairKey('l2', src, dst)}|${type}`;
    p.layers.push({
      id: 'eth',
      brief: `${src} → ${dst}`,
      name: m.name,
      osi: m.osi,
      role: m.role,
      start: o,
      end: off,
      fields: [
        f(m.dst, dst === 'ff:ff:ff:ff:ff:ff' ? m.toEveryone(dst) : dst, m.dstHelp),
        f(m.src, src, m.srcHelp),
        ...(vlan === undefined ? [] : [f(m.vlan, vlan, m.vlanHelp)]),
        f(m.type, typeName, m.typeHelp),
      ],
    });
    network(p, d, off, type);
  }

  function arp(p: Packet, d: Uint8Array, o: number) {
    const m = L.arp;
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
    p.info = { arp: op === 1 ? 'request' : 'reply' };
    p.flowKey = pairKey('arp', senderIp, targetIp);
    if (senderIp === targetIp) p.summary = m.announce(senderIp);
    else if (senderIp === '0.0.0.0') p.summary = m.probe(targetIp);
    else if (op === 1) p.summary = m.ask(targetIp, senderIp);
    else p.summary = m.answer(senderIp, senderMac);
    p.layers.push({
      id: 'arp',
      brief: op === 1 ? m.request : m.reply,
      name: 'ARP',
      osi: m.osi,
      role: m.role,
      start: o,
      end: o + 28,
      fields: [
        f(m.kind, op === 1 ? m.request : m.reply, m.kindHelp),
        f(m.senderIp, senderIp),
        f(m.senderMac, senderMac),
        f(m.targetIp, targetIp),
        f(m.targetMac, op === 1 ? m.unknownMac : targetMac),
      ],
    });
  }

  function ip4(p: Packet, d: Uint8Array, o: number) {
    const m = L.ip;
    need(d, o, 20);
    const ihl = (d[o] & 15) * 4;
    const total = u16(d, o + 2);
    const flagsFrag = u16(d, o + 6);
    const proto = d[o + 9];
    const src = ipv4(d, o + 12);
    const dst = ipv4(d, o + 16);
    const end = total ? Math.min(d.length, o + total) : d.length;
    const fragOffset = (flagsFrag & 0x1fff) * 8;
    const moreFragments = (flagsFrag & 0x2000) !== 0;
    p.src = src;
    p.dst = dst;
    p.proto = 'IPv4';
    p.summary = m.summary4(ipProto(proto));
    p.flowKey = `${pairKey('ip', src, dst)}|${proto}`;
    p.layers.push({
      id: 'ipv4',
      brief: `${src} → ${dst}`,
      name: 'IPv4',
      osi: m.osi,
      role: m.role4,
      start: o,
      end: o + ihl,
      fields: [
        f(m.src, src, m.srcHelp4),
        f(m.dst, dst),
        f(m.ttl, d[o + 8], L.packet.ttlHelp),
        f(m.inner4, ipProto(proto), m.innerHelp),
        f(m.totalLength, L.packet.bytes(total)),
        f(m.fragment, fragOffset || moreFragments ? m.fragmentPiece(fragOffset, moreFragments) : flagsFrag & 0x4000 ? m.dontFragment : m.notFragmented, m.fragmentHelp),
        f(m.id, u16(d, o + 4), m.idHelp),
      ],
    });
    if (fragOffset > 0) {
      p.summary = m.laterFragment;
      return;
    }
    transport(p, d, o + ihl, end, proto);
  }

  function ip6(p: Packet, d: Uint8Array, o: number) {
    const m = L.ip;
    need(d, o, 40);
    const payloadLen = u16(d, o + 4);
    let next = d[o + 6];
    const src = ipv6(d, o + 8);
    const dst = ipv6(d, o + 24);
    const end = payloadLen ? Math.min(d.length, o + 40 + payloadLen) : d.length;
    let off = o + 40;
    let laterFragment = false;
    // 확장 헤더 건너뛰기
    while (next === 0 || next === 43 || next === 60 || next === 44) {
      need(d, off, 8);
      const len = next === 44 ? 8 : (d[off + 1] + 1) * 8;
      if (next === 44 && u16(d, off + 2) & 0xfff8) laterFragment = true;
      next = d[off];
      off += len;
    }
    p.src = src;
    p.dst = dst;
    p.proto = 'IPv6';
    p.summary = m.summary6(ipProto(next));
    p.flowKey = `${pairKey('ip', src, dst)}|${next}`;
    p.layers.push({
      id: 'ipv6',
      brief: `${src} → ${dst}`,
      name: 'IPv6',
      osi: m.osi,
      role: m.role6,
      start: o,
      end: off,
      fields: [
        f(m.src, src, m.srcHelp6),
        f(m.dst, dst),
        f(m.hopLimit, d[o + 7], L.packet.ttlHelp),
        f(m.inner6, ipProto(next)),
        f(m.payloadLength, L.packet.bytes(payloadLen)),
      ],
    });
    if (laterFragment) {
      p.summary = m.laterFragment;
      return;
    }
    transport(p, d, off, end, next);
  }

  function transport(p: Packet, d: Uint8Array, o: number, end: number, proto: number) {
    if (proto === 6) tcp(p, d, o, end);
    else if (proto === 17) udp(p, d, o, end);
    else if (proto === 1) icmp(p, d, o, end, false);
    else if (proto === 58) icmp(p, d, o, end, true);
  }

  function icmp(p: Packet, d: Uint8Array, o: number, end: number, v6: boolean) {
    const m = L.icmp;
    need(d, o, 8);
    const type = d[o];
    const isEcho = v6 ? type === 128 || type === 129 : type === 0 || type === 8;
    const meaning = (v6 ? m.v6 : m.v4)[type] ?? m.typeN(type);
    p.proto = v6 ? 'ICMPv6' : 'ICMP';
    p.appLabel = isEcho ? 'PING' : p.proto;
    p.info = { icmp: { type, code: d[o + 1], v6, ...(isEcho ? { echo: type === 8 || type === 128 ? 'request' : 'reply', seq: u16(d, o + 6) } : {}) } };
    p.summary = meaning;
    p.flowKey = pairKey(v6 ? 'icmp6' : 'icmp', p.src, p.dst);
    p.layers.push({
      id: 'icmp',
      brief: meaning,
      name: p.proto,
      osi: m.osi,
      role: m.role,
      start: o,
      end,
      fields: [
        f(m.type, `${type} — ${meaning}`),
        f(m.code, d[o + 1]),
        ...(isEcho ? [f(m.id, u16(d, o + 4), m.idHelp), f(m.seq, u16(d, o + 6), m.seqHelp)] : []),
      ],
    });
  }

  function tcp(p: Packet, d: Uint8Array, o: number, end: number) {
    const m = L.tcp;
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
    p.summary = payload.length ? L.data.sent(payload.length) : m.control(flagNames.join(', '));
    p.layers.push({
      id: 'tcp',
      brief: `${sp} → ${dp}${flagNames.length ? ` · ${flagNames.join('+')}` : ''}`,
      name: 'TCP',
      osi: m.osi,
      role: m.role,
      start: o,
      end: headerEnd,
      fields: [
        f(m.srcPort, portText(sp), L.packet.portHelp),
        f(m.dstPort, portText(dp)),
        f(m.flags, flagNames.join(' + ') || L.packet.none, m.flagsHelp),
        f(m.seq, seq, m.seqHelp),
        f(m.ack, flags & 0x10 ? ack : L.packet.none, m.ackHelp),
        f(m.window, u16(d, o + 14), m.windowHelp),
        f(m.payload, L.packet.bytes(payload.length)),
      ],
    });
    if (payload.length === 0) return;
    // TCP로 보내는 DNS는 메시지 앞에 2바이트 길이가 붙는다. 한 패킷에 온전히 담긴 것만 해석한다.
    if ((sp === 53 || dp === 53) && payload.length >= 14 && u16(d, headerEnd) >= 12 && u16(d, headerEnd) <= payload.length - 2) {
      dns(p, d, headerEnd + 2, end, 'DNS');
      return;
    }
    if (http(p, d, headerEnd, end) || tls(p, d, headerEnd, end, sp === 443 || dp === 443)) return;
    dataLayer(p, d, headerEnd, end);
  }

  function udp(p: Packet, d: Uint8Array, o: number, end: number) {
    const m = L.udp;
    need(d, o, 8);
    const sp = u16(d, o);
    const dp = u16(d, o + 2);
    const bodyStart = o + 8;
    p.srcPort = sp;
    p.dstPort = dp;
    p.proto = 'UDP';
    p.flowKey = pairKey('udp', `${p.src}#${sp}`, `${p.dst}#${dp}`);
    p.summary = L.data.sent(Math.max(end - bodyStart, 0));
    p.layers.push({
      id: 'udp',
      brief: `${sp} → ${dp}`,
      name: 'UDP',
      osi: m.osi,
      role: m.role,
      start: o,
      end: bodyStart,
      fields: [f(m.srcPort, portText(sp), L.packet.portHelp), f(m.dstPort, portText(dp)), f(m.length, L.packet.bytes(u16(d, o + 4)))],
    });
    if (end <= bodyStart) return;
    const has = (port: number) => sp === port || dp === port;
    if (has(53)) dns(p, d, bodyStart, end, 'DNS');
    else if (has(5353)) dns(p, d, bodyStart, end, 'mDNS');
    else if (has(5355)) dns(p, d, bodyStart, end, 'LLMNR');
    else if (has(67) || has(68)) dhcp(p, d, bodyStart, end);
    else if (has(443) && d[bodyStart] & 0x40) {
      // QUIC 패킷은 첫 바이트의 0x40 비트가 항상 켜져 있다
      p.proto = 'QUIC';
      p.appLabel = 'QUIC';
      p.summary = L.data.sentQuic(end - bodyStart);
      dataLayer(p, d, bodyStart, end, L.data.roleQuic);
    } else dataLayer(p, d, bodyStart, end);
  }

  function dataLayer(p: Packet, d: Uint8Array, o: number, end: number, role?: string) {
    const m = L.data;
    const port = [p.dstPort, p.srcPort].find((x) => x !== undefined && x in KNOWN_PORTS);
    const known = port === undefined ? undefined : KNOWN_PORTS[port];
    if (known && port !== undefined && !p.appLabel) {
      p.appLabel = known;
      p.summary = m.sentKnown(L.ports[port], end - o, known);
    }
    p.layers.push({
      id: 'data',
      brief: L.packet.bytes(end - o),
      name: p.appLabel ?? m.name,
      osi: m.osi,
      role: role ?? (known && port !== undefined ? m.roleKnown(known, L.ports[port]) : m.roleUnknown),
      start: o,
      end,
      fields: [f(m.length, L.packet.bytes(end - o)), f(m.preview, printable(d.subarray(o, end)), m.previewHelp)],
    });
  }

  const dnsType = (t: number) => (DNS_TYPES[t] ? `${DNS_TYPES[t]} (${L.dns.types[t]})` : L.dns.typeN(t));

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
    return [parts.join('.') || L.dns.root, after < 0 ? o : after];
  }

  function dns(p: Packet, d: Uint8Array, o: number, end: number, label: string) {
    const m = L.dns;
    need(d, o, 12);
    const flags = u16(d, o + 2);
    const response = (flags & 0x8000) !== 0;
    const rcode = flags & 15;
    const qd = u16(d, o + 4);
    const an = u16(d, o + 6);
    const fields: Field[] = [f(m.kind, response ? m.response : m.query), f(m.id, `0x${hex(u16(d, o), 4)}`, m.idHelp)];
    p.proto = label;
    p.appLabel = label;
    p.info = { dns: { response, rcode, answers: an } };
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
        fields.push(f(m.query, m.questionValue(name, dnsType(type)), m.questionHelp));
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
        else value = `(${L.packet.bytes(rdLen)})`;
        if (type === 1 || type === 28) {
          answers.push(value);
          (p.names ??= []).push([value, qname || name]);
        }
        fields.push(f(m.response, m.answerValue(name, value, DNS_TYPES[type] ?? String(type), ttl), m.answerHelp));
        off = rd + rdLen;
      }
    } catch {
      p.truncated = true;
    }
    if (response && rcode) fields.push(f(m.result, rcode === 3 ? m.nxdomain : m.errorCode(rcode)));
    p.host = qname || undefined;
    if (!response) p.summary = m.ask(qname, m.types[qtype] ?? m.info);
    else if (rcode === 3) p.summary = m.noSuchName(qname);
    else if (answers.length) p.summary = m.resolved(qname, answers[0], answers.length - 1);
    else if (an === 0) p.summary = m.noData(qname);
    else p.summary = m.answered(qname, an);
    p.layers.push({ id: 'dns', brief: `${response ? m.response : m.query}${qname ? `: ${qname}` : ''}`, name: label, osi: m.osi, role: label === 'DNS' ? m.role : m.roleLocal, start: o, end, fields });
  }

  function dhcp(p: Packet, d: Uint8Array, o: number, end: number) {
    const m = L.dhcp;
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
      else if (code === 50) extra.push(f(m.wanted, ipv4(d, v)));
      else if (code === 1) extra.push(f(m.mask, ipv4(d, v), m.maskHelp));
      else if (code === 3) extra.push(f(m.router, ipv4(d, v), m.routerHelp));
      else if (code === 6) extra.push(f(m.dnsServer, ipv4(d, v)));
      else if (code === 51) extra.push(f(m.lease, m.leaseValue(u32(d, v)), m.leaseHelp));
      else if (code === 12) extra.push(f(m.hostname, utf8(d.subarray(v, v + len))));
      i = v + len;
    }
    const name = DHCP_TYPES[type] ?? '?';
    const meaning = m.types[type] ?? m.generic;
    p.proto = 'DHCP';
    p.appLabel = 'DHCP';
    p.fromClient = op === 1;
    p.info = { dhcp: type };
    p.flowKey = `dhcp|${xid}`;
    p.summary = type === 2 || type === 5 ? `${meaning} — ${yourIp} (${name})` : `${meaning} (${name})`;
    p.layers.push({
      id: 'dhcp',
      brief: name,
      name: 'DHCP',
      osi: m.osi,
      role: m.role,
      start: o,
      end,
      fields: [
        f(m.message, `${name} — ${meaning}`),
        f(m.xid, `0x${hex(xid, 8)}`, m.xidHelp),
        f(m.mac, mac(d, o + 28)),
        ...(yourIp === '0.0.0.0' ? [] : [f(m.assigned, yourIp)]),
        ...extra,
      ],
    });
  }

  function http(p: Packet, d: Uint8Array, o: number, end: number): boolean {
    const m = L.http;
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
    const fields: Field[] = [];
    p.proto = 'HTTP';
    p.appLabel = 'HTTP';
    if (req) {
      const [, method, path] = req;
      const what = m.methods[method] ?? method;
      p.host = headers.find(([k]) => k.toLowerCase() === 'host')?.[1];
      p.info = { http: { method } };
      p.summary = m.request(method, path.length > 60 ? `${path.slice(0, 60)}…` : path, what, path === '/');
      fields.push(f(m.method, `${method} — ${what}`, m.methodHelp));
      fields.push(f(m.path, path, m.pathHelp));
    } else if (res) {
      const [, status, reason] = res;
      const meaning = m.status[status] ?? m.statusClass(status[0]);
      p.info = { http: { status: Number(status), reason } };
      p.summary = `${status} ${reason} — ${meaning}`;
      fields.push(f(m.statusLabel, `${status} ${reason} — ${meaning}`, m.statusHelp));
    }
    for (const [k, v] of headers) fields.push(f(k, v.length > 200 ? `${v.slice(0, 200)}…` : v, m.headerHelp[k.toLowerCase()]));
    if (headEnd >= 0) {
      const body = text.slice(headEnd).replace(/^\s+/, '');
      if (body) fields.push(f(m.body, body.length > 300 ? `${body.slice(0, 300)}…` : body, m.bodyHelp));
    }
    p.layers.push({ id: 'http', brief: text.slice(0, text.search(/\r?\n/)).slice(0, 80), name: 'HTTP', osi: m.osi, role: m.role, start: o, end, fields });
    return true;
  }

  function tls(p: Packet, d: Uint8Array, o: number, end: number, web: boolean): boolean {
    const m = L.tls;
    const isRecord = (i: number) => i + 5 <= end && d[i] >= 20 && d[i] <= 23 && d[i + 1] === 3 && d[i + 2] <= 4;
    if (!isRecord(o)) return false;
    /** [프로토콜 용어, 쉬운 설명] */
    const messages: [string, string][] = [];
    let sni: string | undefined;
    // Change Cipher Spec 뒤의 핸드셰이크 메시지는 암호화되어 있어 종류를 읽을 수 없다
    let encrypted = false;
    const info: PacketInfo = {};
    let i = o;
    while (isRecord(i) && messages.length < 8) {
      const type = d[i];
      const len = u16(d, i + 3);
      if (type === 22) {
        const kind = d[i + 5];
        const bodyLen = (d[i + 6] << 16) | u16(d, i + 7);
        if (!encrypted && TLS_HANDSHAKE[kind] && bodyLen + 4 <= len) {
          messages.push([TLS_HANDSHAKE[kind], m.handshake[kind]]);
          if (kind === 1) sni = tlsServerName(d, i + 5, Math.min(end, i + 5 + len));
          if (kind === 1 || kind === 2) info.tlsHello ??= kind === 1 ? 'client' : 'server';
        } else messages.push(['Handshake', m.encryptedHandshake]);
      } else {
        // 암호화되기 전의 경고는 2바이트(심각도, 사유)라서 읽을 수 있다
        if (type === 20) encrypted = true;
        if (type === 21 && len === 2 && i + 7 <= end) info.tlsAlert = { fatal: d[i + 5] === 2, code: d[i + 6] };
        messages.push([TLS_RECORDS[type], m.records[type]]);
      }
      i += 5 + len;
    }
    p.proto = 'TLS';
    p.appLabel = web ? 'HTTPS' : 'TLS';
    p.host = sni;
    p.info = info;
    p.summary = messages
      .slice(0, 3)
      .map(([name, meaning]) => (name === 'Application Data' ? meaning : `${meaning} (${name})`))
      .join(' + ');
    if (sni) p.summary += m.goingTo(sni);
    p.layers.push({
      id: 'tls',
      brief: messages.map(([name]) => name).join(' + '),
      name: 'TLS',
      osi: m.osi,
      role: m.role,
      start: o,
      end,
      fields: [
        f(m.version, TLS_VERSIONS[u16(d, o + 1)] ?? '?', m.versionHelp),
        ...messages.map(([name, meaning]) => f(m.message, `${name} — ${meaning}`)),
        ...(sni ? [f(m.sni, sni, m.sniHelp)] : []),
      ],
    });
    return true;
  }

  return dissect;
}
