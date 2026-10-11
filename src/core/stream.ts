import { utf8 } from './bytes.ts';
import { headerLines, REQUEST_LINE, STATUS_LINE } from './httpline.ts';
import type { Flow } from './types.ts';

/** TCP 조각 하나: 스트림 안에서의 위치(offset)와 내용, 실어 온 패킷 번호 */
export interface Segment {
  offset: number;
  data: Uint8Array;
  no: number;
  /** 캡처할 때 패킷의 앞부분만 저장해서 이 조각의 뒤쪽이 없음 */
  short?: boolean;
}

/** 한 방향의 조각들을 순서대로 이어 붙인 결과 */
export interface Stream {
  data: Uint8Array;
  /** 이어 붙인 데이터의 어느 구간이 어느 패킷에서 왔는지 */
  pieces: { start: number; end: number; no: number }[];
  /** 더 잇지 못하고 멈춘 까닭. gap: 중간 조각이 캡처에 없음 · short: 앞부분만 저장된 패킷 · limit: 너무 김 */
  stopped?: 'gap' | 'short' | 'limit';
}

/** 한 방향에서 이어 붙이는 최대 크기 */
const STREAM_LIMIT = 4 * 1024 * 1024;

/**
 * 조각을 순서대로 이어 붙인다. 순서가 바뀐 조각은 제자리에 넣고, 다시 온 조각(재전송)은 버린다.
 * start는 스트림의 첫 바이트 위치로, 연결 시작(SYN)을 봤다면 1이다.
 */
export function reassemble(segments: Segment[], start: number, limit = STREAM_LIMIT): Stream {
  const sorted = [...segments].sort((a, b) => a.offset - b.offset || a.no - b.no);
  const parts: Uint8Array[] = [];
  const pieces: Stream['pieces'] = [];
  let pos = start;
  let size = 0;
  let stopped: Stream['stopped'];
  for (const seg of sorted) {
    const end = seg.offset + seg.data.length;
    if (end <= pos) continue;
    if (seg.offset > pos) {
      stopped = 'gap';
      break;
    }
    if (size >= limit) {
      stopped = 'limit';
      break;
    }
    const fresh = seg.data.subarray(pos - seg.offset);
    parts.push(fresh);
    pieces.push({ start: size, end: size + fresh.length, no: seg.no });
    size += fresh.length;
    pos = end;
    if (seg.short) {
      stopped = 'short';
      break;
    }
  }
  const data = new Uint8Array(size);
  let o = 0;
  for (const part of parts) {
    data.set(part, o);
    o += part.length;
  }
  return { data, pieces, stopped };
}

export interface HttpMessage {
  kind: 'request' | 'response';
  startLine: string;
  method?: string;
  path?: string;
  status?: number;
  headers: [string, string][];
  body: Uint8Array;
  /** Content-Length 헤더가 알린 본문 길이 */
  declared?: number;
  /**
   * complete: 끝까지 있음 · cut: 일부만 있음 ·
   * until-close: 길이를 알리지 않아 연결이 닫힐 때까지를 본문으로 봄
   */
  state: 'complete' | 'cut' | 'until-close';
  /** 본문이 일부만 있는 까닭. end는 캡처가 거기서 끝났다는 뜻이다. */
  cutBy?: 'gap' | 'short' | 'limit' | 'end';
  chunked: boolean;
  /** Content-Encoding (gzip 등). 있으면 본문을 풀지 않는다. */
  encoding?: string;
  contentType?: string;
  headerPackets: number[];
  bodyPackets: number[];
}

function indexOf(data: Uint8Array, pattern: number[], from: number): number {
  outer: for (let i = from; i + pattern.length <= data.length; i++) {
    for (let j = 0; j < pattern.length; j++) if (data[i + j] !== pattern[j]) continue outer;
    return i;
  }
  return -1;
}

const CRLF = [13, 10];

/** 조각(chunked) 전송을 이어 붙인다. 끝까지 없으면 있는 데까지만 돌려준다. */
function dechunk(data: Uint8Array, from: number): { body: Uint8Array; end: number; complete: boolean } {
  const parts: Uint8Array[] = [];
  let o = from;
  let complete = false;
  for (;;) {
    const lineEnd = indexOf(data, CRLF, o);
    if (lineEnd < 0) break;
    const size = parseInt(utf8(data.subarray(o, lineEnd)).split(';')[0].trim(), 16);
    if (Number.isNaN(size)) break;
    const start = lineEnd + 2;
    if (size === 0) {
      // 마지막 조각 뒤에는 빈 줄(또는 덧붙인 헤더)이 온다
      const tail = indexOf(data, CRLF, start);
      o = tail < 0 ? data.length : tail + 2;
      complete = tail >= 0;
      break;
    }
    if (start + size > data.length) {
      parts.push(data.subarray(start));
      o = data.length;
      break;
    }
    parts.push(data.subarray(start, start + size));
    o = start + size + 2;
  }
  const body = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    body.set(part, at);
    at += part.length;
  }
  return { body, end: Math.min(o, data.length), complete };
}

/**
 * 이어 붙인 스트림에서 HTTP/1.x 메시지를 차례로 읽어 낸다.
 * 응답을 읽을 때는 요청들의 방식(methods)을 넘겨야 한다: HEAD에 대한 응답은 길이를 알려도 본문이 없다.
 */
export function parseHttp(stream: Stream, kind: 'request' | 'response', methods: string[] = []): HttpMessage[] {
  const { data } = stream;
  const out: HttpMessage[] = [];
  const packetsIn = (start: number, end: number) => [...new Set(stream.pieces.filter((p) => p.start < end && p.end > start).map((p) => p.no))];
  let off = 0;
  /** 지금 읽는 응답이 몇 번째 요청에 대한 것인지. 1xx 중간 응답은 요청을 소비하지 않는다. */
  let answering = 0;
  while (off < data.length) {
    const headEnd = indexOf(data, [13, 10, 13, 10], off);
    if (headEnd < 0) break;
    const lines = utf8(data.subarray(off, headEnd)).split('\r\n');
    const startLine = lines[0];
    const request = REQUEST_LINE.exec(startLine);
    const status = STATUS_LINE.exec(startLine);
    if (kind === 'request' ? !request : !status) break;
    const headers = headerLines(lines.slice(1));
    const get = (name: string) => headers.find(([k]) => k.toLowerCase() === name)?.[1];
    const bodyStart = headEnd + 4;
    const code = status ? Number(status[1]) : undefined;
    const lengthHeader = get('content-length');
    const declared = lengthHeader !== undefined && /^\d+$/.test(lengthHeader) ? Number(lengthHeader) : undefined;
    const chunked = /chunked/i.test(get('transfer-encoding') ?? '');
    const interim = code !== undefined && code < 200;
    const bodiless = code !== undefined && (interim || code === 204 || code === 304 || methods[answering] === 'HEAD');
    if (code !== undefined && !interim) answering++;

    let body: Uint8Array;
    let end: number;
    let state: HttpMessage['state'] = 'complete';
    if (bodiless) {
      body = data.subarray(bodyStart, bodyStart);
      end = bodyStart;
    } else if (chunked) {
      const result = dechunk(data, bodyStart);
      body = result.body;
      end = result.end;
      if (!result.complete) state = 'cut';
    } else if (declared !== undefined) {
      end = Math.min(bodyStart + declared, data.length);
      body = data.subarray(bodyStart, end);
      if (body.length < declared) state = 'cut';
    } else if (kind === 'request') {
      body = data.subarray(bodyStart, bodyStart);
      end = bodyStart;
    } else {
      // 길이를 알리지 않은 응답은 연결이 닫힐 때까지가 본문이다
      end = data.length;
      body = data.subarray(bodyStart, end);
      state = 'until-close';
    }

    out.push({
      kind,
      startLine,
      method: request?.[1],
      path: request?.[2],
      status: code,
      headers,
      body,
      declared,
      state,
      cutBy: state === 'cut' ? (stream.stopped ?? 'end') : undefined,
      chunked,
      encoding: get('content-encoding'),
      contentType: get('content-type'),
      headerPackets: packetsIn(off, bodyStart),
      bodyPackets: body.length ? packetsIn(bodyStart, end) : [],
    });
    if (state !== 'complete') break;
    off = end;
  }
  return out;
}

/** 요청 하나와 그에 대한 응답. interim은 최종 응답 전에 온 1xx 응답(100 Continue 등). */
export interface Exchange {
  request?: HttpMessage;
  interim: HttpMessage[];
  response?: HttpMessage;
}

/** 요청과 응답을 차례대로 짝짓는다. 1xx 중간 응답은 같은 요청에 붙인다. */
export function pairExchanges(requests: HttpMessage[], responses: HttpMessage[]): Exchange[] {
  const exchanges: Exchange[] = requests.map((request) => ({ request, interim: [] }));
  let i = 0;
  for (const response of responses) {
    exchanges[i] ??= { interim: [] };
    if (response.status !== undefined && response.status < 200) exchanges[i].interim.push(response);
    else exchanges[i++].response = response;
  }
  return exchanges;
}

export interface HttpConversation {
  exchanges: Exchange[];
  /** 중간 패킷이 빠져 있어 그 뒤를 잇지 못한 방향이 있음 */
  gap: boolean;
  /** 너무 길어서 앞부분만 이은 방향이 있음 */
  clipped: boolean;
}

function direction(flow: Flow, fromA: boolean): Stream {
  const side = fromA ? 'a' : 'b';
  const isn = flow.tcp!.isn[side] ?? 0;
  const segments: Segment[] = [];
  let lowest = Infinity;
  for (const p of flow.packets) {
    if (p.fromA !== fromA || !p.tcp || p.tcp.payloadLen === 0) continue;
    const offset = (p.tcp.seq - isn) >>> 0;
    if (offset < lowest) lowest = offset;
    segments.push({ offset, data: p.data.subarray(p.tcp.payloadStart, p.tcp.payloadStart + p.tcp.captured), no: p.no, short: p.tcp.captured < p.tcp.payloadLen });
  }
  // 연결 시작을 봤다면 데이터는 1에서 시작한다. 못 봤다면 캡처된 첫 조각부터 잇는다.
  const sawStart = fromA ? flow.tcp!.syn : flow.tcp!.synAck;
  return reassemble(segments, sawStart ? 1 : segments.length ? lowest : 0);
}

const cache = new WeakMap<Flow, { size: number; result: HttpConversation }>();

/** 암호화되지 않은 HTTP 대화를 패킷이 아니라 메시지 단위로 읽는다 */
export function httpConversation(flow: Flow): HttpConversation {
  const hit = cache.get(flow);
  if (hit && hit.size === flow.packets.length) return hit.result;
  const result: HttpConversation = { exchanges: [], gap: false, clipped: false };
  if (flow.tcp) {
    const up = direction(flow, true);
    const down = direction(flow, false);
    const requests = parseHttp(up, 'request');
    const responses = parseHttp(
      down,
      'response',
      requests.map((r) => r.method ?? ''),
    );
    result.exchanges = pairExchanges(requests, responses);
    result.gap = up.stopped === 'gap' || down.stopped === 'gap';
    result.clipped = up.stopped === 'limit' || down.stopped === 'limit';
  }
  cache.set(flow, { size: flow.packets.length, result });
  return result;
}
