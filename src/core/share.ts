// 대화 하나를 URL에 담아 공유한다: pcap 바이트 → 압축 → base64url.
// URL의 # 뒤에 넣기 때문에 서버로 전달되지 않는다.
import type { RawPacket } from './reader.ts';
import type { Packet } from './types.ts';

/** 이보다 긴 링크는 메신저나 문서에서 잘리기 쉬워서 만들지 않는다 */
export const SHARE_URL_LIMIT = 8000;

/** 받는 쪽 안전장치: 조작된 링크로 메모리를 다 쓰게 만들지 못하도록 한다 */
const MAX_ENCODED = 64 * 1024;
const MAX_DECODED = 1024 * 1024;

const HEADERS_ONLY = 'h';
const FULL = 'f';

export class ShareError extends Error {}

/**
 * 패킷에서 헤더가 끝나는 위치. 내용(응용 계층 데이터)은 이 뒤에 있다.
 * ICMP 오류 알림은 어느 통신에 대한 것인지 알려 주는 원래 패킷의 헤더까지 남긴다.
 */
function headerEnd(p: Packet): number {
  let end = 0;
  for (const layer of p.layers) {
    if (layer.id === 'icmp') {
      const { icmp } = p.info ?? {};
      const notice = icmp && !icmp.v6 && !icmp.echo;
      const inner = layer.start + 8;
      end = notice ? Math.min(layer.end, inner + (p.data[inner] & 15) * 4 + 8) : Math.min(layer.end, inner);
    } else if (layer.id === 'eth' || layer.id === 'arp' || layer.id === 'ipv4' || layer.id === 'ipv6' || layer.id === 'tcp' || layer.id === 'udp') {
      end = layer.end;
    }
  }
  return end;
}

/**
 * 대화의 패킷들로 pcap 파일을 만든다. 시각은 첫 패킷을 0으로 다시 맞춰서, 언제 캡처했는지는 담지 않는다.
 * pcap 파일 하나는 연결 방식이 하나뿐이라, 첫 패킷과 방식이 다른 패킷은 뺀다.
 */
export function flowCapture(packets: Packet[], raws: RawPacket[], headersOnly: boolean): Uint8Array {
  const linkType = raws[0]?.linkType ?? 1;
  const t0 = raws[0]?.ts ?? 0;
  const records = raws.map((raw, i) => ({ raw, data: headersOnly ? raw.data.subarray(0, headerEnd(packets[i])) : raw.data })).filter((r) => r.raw.linkType === linkType);
  const out = new Uint8Array(24 + records.reduce((n, r) => n + 16 + r.data.length, 0));
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 262144, true);
  view.setUint32(20, linkType, true);
  let o = 24;
  for (const { raw, data } of records) {
    const elapsed = Math.max(raw.ts - t0, 0);
    const seconds = Math.floor(elapsed);
    view.setUint32(o, seconds, true);
    view.setUint32(o + 4, Math.min(Math.round((elapsed - seconds) * 1e6), 999999), true);
    view.setUint32(o + 8, data.length, true);
    view.setUint32(o + 12, raw.origLen, true);
    out.set(data, o + 16);
    o += 16 + data.length;
  }
  return out;
}

async function collect(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let size = 0;
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel();
      throw new ShareError('too large');
    }
    parts.push(value);
  }
  const out = new Uint8Array(size);
  let o = 0;
  for (const part of parts) {
    out.set(part, o);
    o += part.length;
  }
  return out;
}

/** 스트림에 쓰다가 실패해도 읽는 쪽에서 오류를 받도록, 쓰기는 기다리지 않고 결과만 받는다 */
function pipe(bytes: Uint8Array, transform: CompressionStream | DecompressionStream): ReadableStream<Uint8Array> {
  const writer = transform.writable.getWriter();
  writer.write(bytes as BufferSource).catch(() => {});
  writer.close().catch(() => {});
  return transform.readable as ReadableStream<Uint8Array>;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(text: string): Uint8Array {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/** 캡처를 URL에 넣을 글자로 바꾼다 */
export async function encodeShare(capture: Uint8Array, headersOnly: boolean): Promise<string> {
  const packed = await collect(pipe(capture, new CompressionStream('deflate-raw')), Infinity);
  return `${headersOnly ? HEADERS_ONLY : FULL}.${toBase64Url(packed)}`;
}

/** URL의 글자를 캡처로 되돌린다. 손상되었거나 지나치게 크면 ShareError를 던진다. */
export async function decodeShare(value: string): Promise<{ capture: Uint8Array; headersOnly: boolean }> {
  const dot = value.indexOf('.');
  const mode = value.slice(0, dot);
  if ((mode !== HEADERS_ONLY && mode !== FULL) || value.length > MAX_ENCODED) throw new ShareError('bad link');
  try {
    const capture = await collect(pipe(fromBase64Url(value.slice(dot + 1)), new DecompressionStream('deflate-raw')), MAX_DECODED);
    return { capture, headersOnly: mode === HEADERS_ONLY };
  } catch {
    throw new ShareError('bad link');
  }
}
