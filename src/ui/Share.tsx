import { useEffect, useState } from 'react';
import { encodeShare, flowCapture, SHARE_URL_LIMIT } from '../core/share.ts';
import type { RawPacket } from '../core/reader.ts';
import type { Flow } from '../core/types.ts';
import { useMessages } from './locale.ts';

/** 대화 하나를 담은 링크를 만들어 복사하게 해 주는 패널 */
export function SharePanel({ flow, raws }: { flow: Flow; raws: RawPacket[] }) {
  const m = useMessages().share;
  const [headersOnly, setHeadersOnly] = useState(true);
  const [link, setLink] = useState('');
  const [copy, setCopy] = useState<'idle' | 'done' | 'failed'>('idle');

  useEffect(() => {
    let current = true;
    setLink('');
    setCopy('idle');
    encodeShare(flowCapture(flow.packets, raws, headersOnly), headersOnly).then((value) => {
      if (!current) return;
      const url = new URL(location.href);
      url.hash = new URLSearchParams({ capture: value }).toString();
      setLink(url.href);
    });
    return () => {
      current = false;
    };
  }, [flow, headersOnly]);

  const tooLong = link.length > SHARE_URL_LIMIT;

  function copyLink() {
    navigator.clipboard.writeText(link).then(
      () => setCopy('done'),
      () => setCopy('failed'),
    );
  }

  return (
    <section className="share-panel">
      <label>
        <input id="share-headers" type="radio" name="share-mode" checked={headersOnly} onChange={() => setHeadersOnly(true)} /> <b>{m.headers}</b>
        <small>{m.headersHelp}</small>
      </label>
      <label>
        <input id="share-full" type="radio" name="share-mode" checked={!headersOnly} onChange={() => setHeadersOnly(false)} /> <b>{m.full}</b>
        <small>{m.fullHelp}</small>
      </label>
      <p className="muted">{m.warning}</p>
      {tooLong ? (
        <p className="status warn msg-note">{m.tooLong(link.length, SHARE_URL_LIMIT)}</p>
      ) : (
        <div className="share-link">
          <input id="share-url" className="mono" readOnly value={link} onFocus={(e) => e.target.select()} aria-label={m.copy} />
          <button className="btn primary" onClick={copyLink} disabled={!link}>
            {copy === 'done' ? m.copied : m.copy}
          </button>
        </div>
      )}
      {!tooLong && link && <p className="muted">{copy === 'failed' ? m.copyFailed : m.length(link.length)}</p>}
    </section>
  );
}
