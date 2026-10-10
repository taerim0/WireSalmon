export interface RawPacket {
  /** 초 단위 시각 */
  ts: number;
  linkType: number;
  data: Uint8Array;
  origLen: number;
}

const MAX_BLOCK = 64 * 1024 * 1024;

/** 화면에 보여 줄 문장은 언어별 사전(errors)에서 code로 찾는다 */
export class CaptureError extends Error {
  code: 'format' | 'corrupt';
  constructor(code: 'format' | 'corrupt') {
    super(code);
    this.code = code;
  }
}

/**
 * pcap / pcapng 스트림 해석기.
 * 파일 전체를 한 번에 넣어도 되고, 실시간 캡처처럼 조각으로 나눠 넣어도 된다.
 */
export class CaptureReader {
  private buf: Uint8Array = new Uint8Array(0);
  private format: 'pcap' | 'pcapng' | null = null;
  private le = true;
  private tsUnit = 1e-6;
  private linkType = 1;
  private ifaces: { linkType: number; tsUnit: number }[] = [];

  push(chunk: Uint8Array): RawPacket[] {
    if (this.buf.length === 0) this.buf = chunk;
    else {
      const merged = new Uint8Array(this.buf.length + chunk.length);
      merged.set(this.buf);
      merged.set(chunk, this.buf.length);
      this.buf = merged;
    }
    const out: RawPacket[] = [];
    let off = 0;
    for (;;) {
      const used = this.format === 'pcapng' ? this.pcapngBlock(off, out) : this.format === 'pcap' ? this.pcapRecord(off, out) : this.header(off);
      if (used === 0) break;
      off += used;
    }
    this.buf = this.buf.subarray(off);
    return out;
  }

  private u32(o: number): number {
    const d = this.buf;
    return this.le
      ? (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0
      : ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;
  }

  private u16(o: number): number {
    const d = this.buf;
    return this.le ? d[o] | (d[o + 1] << 8) : (d[o] << 8) | d[o + 1];
  }

  private header(off: number): number {
    const d = this.buf;
    if (d.length - off < 4) return 0;
    const magic = ((d[off] << 24) | (d[off + 1] << 16) | (d[off + 2] << 8) | d[off + 3]) >>> 0;
    if (magic === 0x0a0d0d0a) {
      this.format = 'pcapng';
      return this.pcapngBlock(off, []);
    }
    const kinds: Record<number, [boolean, number]> = {
      0xd4c3b2a1: [true, 1e-6],
      0xa1b2c3d4: [false, 1e-6],
      0x4d3cb2a1: [true, 1e-9],
      0xa1b23c4d: [false, 1e-9],
    };
    const kind = kinds[magic];
    if (!kind) throw new CaptureError('format');
    if (d.length - off < 24) return 0;
    [this.le, this.tsUnit] = kind;
    this.linkType = this.u32(off + 20) & 0xffff;
    this.format = 'pcap';
    return 24;
  }

  private pcapRecord(off: number, out: RawPacket[]): number {
    if (this.buf.length - off < 16) return 0;
    const incl = this.u32(off + 8);
    if (incl > MAX_BLOCK) throw new CaptureError('corrupt');
    if (this.buf.length - off < 16 + incl) return 0;
    out.push({
      ts: this.u32(off) + this.u32(off + 4) * this.tsUnit,
      linkType: this.linkType,
      data: this.buf.subarray(off + 16, off + 16 + incl),
      origLen: this.u32(off + 12),
    });
    return 16 + incl;
  }

  private pcapngBlock(off: number, out: RawPacket[]): number {
    const d = this.buf;
    if (d.length - off < 12) return 0;
    const type = this.u32(off);
    if (type === 0x0a0d0d0a) {
      // 섹션 헤더: 바이트 순서가 여기서 정해진다
      this.le = d[off + 8] === 0x4d;
      this.ifaces = [];
    }
    const total = this.u32(off + 4);
    if (total < 12 || total > MAX_BLOCK) throw new CaptureError('corrupt');
    if (d.length - off < total) return 0;
    const body = off + 8;
    const bodyEnd = off + total - 4;

    if (type === 1) {
      let tsUnit = 1e-6;
      for (let o = body + 8; o + 4 <= bodyEnd; ) {
        const code = this.u16(o);
        const len = this.u16(o + 2);
        if (code === 0) break;
        if (code === 9 && len >= 1) {
          const v = d[o + 4];
          tsUnit = v & 0x80 ? 2 ** -(v & 0x7f) : 10 ** -v;
        }
        o += 4 + ((len + 3) & ~3);
      }
      this.ifaces.push({ linkType: this.u16(body), tsUnit });
    } else if (type === 6) {
      const iface = this.ifaces[this.u32(body)] ?? { linkType: 1, tsUnit: 1e-6 };
      const capLen = Math.min(this.u32(body + 12), bodyEnd - body - 20);
      out.push({
        ts: (this.u32(body + 4) * 2 ** 32 + this.u32(body + 8)) * iface.tsUnit,
        linkType: iface.linkType,
        data: d.subarray(body + 20, body + 20 + capLen),
        origLen: this.u32(body + 16),
      });
    } else if (type === 3) {
      const origLen = this.u32(body);
      out.push({
        ts: 0,
        linkType: this.ifaces[0]?.linkType ?? 1,
        data: d.subarray(body + 4, body + 4 + Math.min(origLen, bodyEnd - body - 4)),
        origLen,
      });
    }
    return total;
  }
}
