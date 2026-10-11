import { Fragment } from 'react';
import { httpConversation, type HttpMessage } from '../core/stream.ts';
import type { Flow } from '../core/types.ts';
import type { Messages } from '../i18n/index.ts';
import { useMessages } from './locale.ts';

const TEXT_LIMIT = 8192;

/** 글자로 보여 줄 수 있는 본문인지: 종류가 글자라고 밝혔거나, 앞부분이 대부분 읽을 수 있는 글자일 때 */
function isText(msg: HttpMessage): boolean {
  if (/text|json|xml|javascript|html|urlencoded/i.test(msg.contentType ?? '')) return true;
  const head = msg.body.subarray(0, 512);
  let readable = 0;
  for (const b of head) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 0x80) readable++;
  return head.length > 0 && readable / head.length > 0.95;
}

/** 본문을 글자로 바꾼다. 서버가 밝힌 문자 집합(예: euc-kr)을 따르고, 모르는 것이면 UTF-8로 읽는다. */
function decodeBody(msg: HttpMessage, bytes: Uint8Array): string {
  const charset = /charset=["']?([\w-]+)/i.exec(msg.contentType ?? '')?.[1];
  try {
    return new TextDecoder(charset ?? 'utf-8').decode(bytes);
  } catch {
    return new TextDecoder().decode(bytes);
  }
}

/** 본문이 온전한지, 어떻게 끝을 알렸는지 */
function stateNote(msg: HttpMessage, m: Messages['msg']): { text: string; warn: boolean } | null {
  if (msg.state === 'cut') {
    if (msg.declared === undefined) return { text: m.chunkedCut, warn: true };
    const say = { gap: m.cutGap, short: m.cutShort, limit: m.cutLimit, end: m.cutEnd }[msg.cutBy ?? 'end'];
    return { text: say(msg.body.length, msg.declared), warn: true };
  }
  if (msg.state === 'until-close') return { text: m.untilClose, warn: false };
  if (msg.chunked) return { text: m.chunked, warn: false };
  if (msg.declared !== undefined && msg.body.length) return { text: m.lengthMatches(msg.declared), warn: false };
  return null;
}

/**
 * 암호화되지 않은 HTTP 대화를 메시지 단위로 보여 준다.
 * 헤더와 본문이 여러 패킷에 나뉘어 와도 하나로 이어서 읽고, 원래 패킷으로 돌아갈 수 있다.
 */
export function HttpMessages(props: { flow: Flow; selected: number | null; onSelect: (no: number) => void }) {
  const { flow, selected, onSelect } = props;
  const L = useMessages();
  const m = L.msg;
  const { exchanges, gap, clipped } = httpConversation(flow);

  const chips = (label: string, numbers: number[]) =>
    numbers.length > 0 && (
      <span className="msg-packets">
        <span className="muted">{label}</span>
        {numbers.map((no) => (
          <button key={no} className={`chip ${no === selected ? 'on' : ''}`} onClick={() => onSelect(no)}>
            #{no}
          </button>
        ))}
      </span>
    );

  const message = (msg: HttpMessage | undefined, missing: string) => {
    if (!msg) return <p className="msg-missing muted">{missing}</p>;
    const note = stateNote(msg, m);
    const encoded = msg.encoding && !/^identity$/i.test(msg.encoding);
    const text = !encoded && msg.body.length > 0 && isText(msg) ? decodeBody(msg, msg.body.subarray(0, TEXT_LIMIT)) : null;
    return (
      <article className={`msg ${msg.kind}`}>
        <header>
          <span className="msg-kind">{msg.kind === 'request' ? m.request : msg.status !== undefined && msg.status < 200 ? m.interim : m.response}</span>
          <code className="msg-start">{msg.startLine}</code>
        </header>
        <div className="msg-part">
          <h4>{m.headers}</h4>
          {chips(m.carriedBy, msg.headerPackets)}
        </div>
        <dl className="msg-headers">
          {msg.headers.map(([key, value], i) => (
            <div key={i}>
              <dt>{key}</dt>
              <dd className="mono">{value}</dd>
            </div>
          ))}
        </dl>
        <div className="msg-part">
          <h4>
            {m.body} <span className="muted">{msg.body.length ? L.packet.bytes(msg.body.length) : m.noBody}</span>
          </h4>
          {chips(m.carriedBy, msg.bodyPackets)}
        </div>
        {note && <p className={note.warn ? 'status warn msg-note' : 'muted msg-note'}>{note.text}</p>}
        {text !== null && <pre className="msg-body mono">{text}</pre>}
        {text !== null && msg.body.length > TEXT_LIMIT && <p className="muted">{m.clipped(TEXT_LIMIT, msg.body.length)}</p>}
        {encoded && msg.body.length > 0 && <p className="muted">{m.encoded(msg.encoding!)}</p>}
        {!encoded && text === null && msg.body.length > 0 && <p className="muted">{m.binary}</p>}
      </article>
    );
  };

  return (
    <div className="messages">
      <p className="muted">{m.intro}</p>
      {exchanges.length === 0 && <p className="empty">{m.none}</p>}
      {exchanges.map((exchange, i) => (
        <section key={i} className="exchange">
          {message(exchange.request, m.noRequest)}
          {exchange.interim.map((msg, j) => (
            <Fragment key={j}>{message(msg, '')}</Fragment>
          ))}
          {message(exchange.response, m.noResponse)}
        </section>
      ))}
      {gap && <p className="status warn msg-note">{m.gap}</p>}
      {clipped && <p className="muted">{m.tooLong}</p>}
    </div>
  );
}
