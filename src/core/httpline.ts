// HTTP/1.x의 첫 줄과 헤더 줄을 읽는 규칙. 패킷 해석과 메시지 잇기가 같은 규칙을 쓰도록 한곳에 둔다.

export const REQUEST_LINE = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP\/1\.[01]$/;
export const STATUS_LINE = /^HTTP\/1\.[01] (\d{3}) ?(.*)$/;

/** "이름: 값" 줄들을 [이름, 값] 목록으로 바꾼다 */
export function headerLines(lines: string[]): [string, string][] {
  const headers: [string, string][] = [];
  for (const line of lines) {
    const i = line.indexOf(':');
    if (i > 0) headers.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return headers;
}
