export const u16 = (d: Uint8Array, o: number) => (d[o] << 8) | d[o + 1];
export const u32 = (d: Uint8Array, o: number) => ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;

export const hex = (n: number, width = 2) => n.toString(16).padStart(width, '0');

export const mac = (d: Uint8Array, o: number) => Array.from(d.subarray(o, o + 6), (b) => hex(b)).join(':');
export const ipv4 = (d: Uint8Array, o: number) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;

export function ipv6(d: Uint8Array, o: number): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) groups.push(u16(d, o + i * 2));
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  const parts = groups.map((g) => g.toString(16));
  if (bestLen < 2) return parts.join(':');
  return `${parts.slice(0, best).join(':')}::${parts.slice(best + bestLen).join(':')}`;
}

const decoder = new TextDecoder();
export const utf8 = (d: Uint8Array) => decoder.decode(d);

/** 사람이 읽을 수 있는 글자만 남긴 미리보기 */
export function printable(d: Uint8Array, max = 64): string {
  let out = '';
  for (let i = 0; i < Math.min(d.length, max); i++) out += d[i] >= 32 && d[i] < 127 ? String.fromCharCode(d[i]) : '.';
  return d.length > max ? `${out}…` : out;
}
