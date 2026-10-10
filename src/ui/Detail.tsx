import { useEffect, useRef, useState, type MouseEvent } from 'react';
import { hex } from '../core/bytes.ts';
import type { Layer, LayerId, Packet } from '../core/types.ts';
import { useMessages } from './locale.ts';
import { seconds } from './views.tsx';

const HEX_LIMIT = 1024;

/** 지금 가리키고 있는 봉투. 바이트 쪽에서 가리킨 경우에는 바이트 창을 따로 스크롤하지 않는다. */
interface Pointed {
  index: number;
  from: 'layer' | 'bytes';
}

/**
 * 패킷 하나를 봉투 단위로 풀어서 보여 준다.
 * 펼침 상태는 봉투 종류별로 기억해서, 다른 패킷으로 넘어가도 같은 봉투가 펼쳐져 있다.
 */
export function PacketDetail({ packet, t0 }: { packet: Packet; t0: number }) {
  const L = useMessages();
  const layers = packet.layers;
  const [hover, setHover] = useState<Pointed | null>(null);
  const [pinned, setPinned] = useState<LayerId | null>(null);
  /** 사용자가 직접 펼치거나 접은 봉투. 건드리지 않은 봉투는 가장 안쪽만 펼친다. */
  const [choices, setChoices] = useState<Map<LayerId, boolean>>(new Map());
  const [all, setAll] = useState(false);
  const [showHelp, setShowHelp] = useState(true);
  const hexRef = useRef<HTMLDivElement>(null);

  useEffect(() => setHover(null), [packet.no]);

  const isOpen = (i: number) => all || (choices.get(layers[i].id) ?? i === layers.length - 1);
  const pinnedIndex = layers.findIndex((l) => l.id === pinned);
  const activeIndex = hover && hover.index < layers.length ? hover.index : pinnedIndex >= 0 ? pinnedIndex : null;
  const active = activeIndex === null ? null : layers[activeIndex];

  // 봉투를 가리키면 그 부분의 첫 바이트가 바이트 창 안에 보이도록 맞춘다
  useEffect(() => {
    const box = hexRef.current;
    if (!box || !active || hover?.from === 'bytes') return;
    const row = box.querySelector<HTMLElement>(`[data-row="${Math.floor(active.start / 16)}"]`);
    if (row) box.scrollTop = row.offsetTop - 4;
  }, [active, hover]);

  /** 누르면 펼치면서 그 봉투의 바이트를 고정 표시하고, 다시 누르면 접는다 */
  function toggle(i: number) {
    const id = layers[i].id;
    const open = isOpen(i);
    const next = new Map(choices);
    if (all) layers.forEach((l) => next.set(l.id, true));
    next.set(id, !open);
    setAll(false);
    setChoices(next);
    setPinned(open ? (pinned === id ? null : pinned) : id);
  }

  function pointAtByte(e: MouseEvent) {
    const offset = Number((e.target as HTMLElement).dataset.o ?? -1);
    if (offset < 0) return;
    // 가장 안쪽 봉투부터 찾는다
    for (let i = layers.length - 1; i >= 0; i--) {
      if (offset >= layers[i].start && offset < layers[i].end) {
        if (hover?.index !== i || hover.from !== 'bytes') setHover({ index: i, from: 'bytes' });
        return;
      }
    }
  }

  return (
    <div className="detail-body">
      <div className="detail-main">
        <p className="muted">{L.ui.detailMeta(packet.no, seconds(packet.ts, t0, L), packet.origLen)}</p>
        <h2>{packet.summary}</h2>
        {packet.truncated && <p className="status warn">{L.ui.truncated}</p>}

        <div className="detail-section">
          <h3>{L.ui.envelopes}</h3>
          <span className="detail-options muted">
            <label>
              <input id="expand-all" type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> {L.ui.expandAll}
            </label>
            <label>
              <input id="show-help" type="checkbox" checked={showHelp} onChange={(e) => setShowHelp(e.target.checked)} /> {L.ui.showHelp}
            </label>
          </span>
        </div>
        <p className="muted">{L.ui.envelopesHint}</p>

        <div className="layers">
          {layers.map((layer, i) => (
            <LayerRow
              key={layer.id}
              layers={layers}
              index={i}
              open={isOpen(i)}
              active={activeIndex === i}
              pinned={pinnedIndex === i}
              showHelp={showHelp}
              onHover={(on) => setHover(on ? { index: i, from: 'layer' } : null)}
              onToggle={() => toggle(i)}
            />
          ))}
        </div>
      </div>

      <div className="hex-panel">
        <div className="detail-section">
          <h3>{L.ui.rawBytes}</h3>
          <span className="muted">{active ? L.ui.showing(active.name) : L.ui.hoverHint}</span>
        </div>
        <div className="hex mono" ref={hexRef} onMouseMove={pointAtByte} onMouseLeave={() => setHover(null)}>
          <HexRows data={packet.data} from={active?.start ?? -1} to={active?.end ?? -1} />
          {packet.data.length > HEX_LIMIT && <p className="muted">{L.ui.hexLimit(HEX_LIMIT, packet.data.length)}</p>}
        </div>
      </div>
    </div>
  );
}

/**
 * 봉투 한 겹. 왼쪽의 색 띠가 겹침을 나타낸다: 바깥 봉투들의 띠가 이 줄 옆까지 이어져 내려온다.
 * 내용은 겹침 깊이와 상관없이 전체 폭을 쓴다.
 */
function LayerRow(props: {
  layers: Layer[];
  index: number;
  open: boolean;
  active: boolean;
  pinned: boolean;
  showHelp: boolean;
  onHover: (on: boolean) => void;
  onToggle: () => void;
}) {
  const { layers, index, open, active, pinned, showHelp, onHover, onToggle } = props;
  const layer = layers[index];
  return (
    <div className="layer-row" data-layer={layer.id}>
      <span className="rails" aria-hidden>
        {layers.slice(0, index + 1).map((outer, i) => (
          <span key={outer.id} className={`rail ${i === index ? 'own' : ''}`} data-layer={outer.id} />
        ))}
      </span>
      <div className={`layer-card ${active ? 'active' : ''} ${pinned ? 'pinned' : ''}`} onMouseEnter={() => onHover(true)} onMouseLeave={() => onHover(false)}>
        <button className="layer-head" onClick={onToggle} aria-expanded={open}>
          <span className="chevron" aria-hidden>
            {open ? '▾' : '▸'}
          </span>
          <b>{layer.name}</b>
          {open ? <span className="layer-osi muted">{layer.osi}</span> : <span className="layer-brief muted mono">{layer.brief}</span>}
        </button>
        {open && (
          <div className="layer-body">
            {showHelp && <p className="layer-role">{layer.role}</p>}
            <dl>
              {layer.fields.map((field, i) => (
                <div key={i} className="field">
                  <dt>{field.label}</dt>
                  <dd>
                    <span className="mono">{field.value}</span>
                    {showHelp && field.help && <small>{field.help}</small>}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}

function HexRows({ data, from, to }: { data: Uint8Array; from: number; to: number }) {
  const rows = [];
  const end = Math.min(data.length, HEX_LIMIT);
  for (let o = 0; o < end; o += 16) {
    const bytes = Array.from(data.subarray(o, Math.min(o + 16, end)));
    const mark = (i: number) => (o + i >= from && o + i < to ? 'hl' : undefined);
    rows.push(
      <div key={o} className="hex-row" data-row={o / 16}>
        <span className="muted">{hex(o, 4)}</span>
        <span className="hex-bytes">
          {bytes.map((b, i) => (
            <span key={i} data-o={o + i} className={mark(i)}>
              {hex(b)}
            </span>
          ))}
        </span>
        <span className="hex-ascii">
          {bytes.map((b, i) => (
            <span key={i} data-o={o + i} className={mark(i)}>
              {b >= 32 && b < 127 ? String.fromCharCode(b) : '·'}
            </span>
          ))}
        </span>
      </div>,
    );
  }
  return rows;
}
