import { useState } from 'react';
import { hex } from '../core/bytes.ts';
import type { Layer, Packet } from '../core/types.ts';
import { seconds } from './views.tsx';

const HEX_LIMIT = 1024;

export function PacketDetail({ packet, t0 }: { packet: Packet; t0: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const [showHelp, setShowHelp] = useState(true);
  const active = hover === null ? null : packet.layers[hover];
  return (
    <div className="detail-body">
      <p className="muted">
        {packet.no}번 패킷 · {seconds(packet.ts, t0)} · {packet.origLen}바이트
      </p>
      <h2>{packet.summary}</h2>
      {packet.truncated && <p className="status warn">패킷이 잘려 있어 일부만 해석했습니다.</p>}

      <div className="detail-section">
        <h3>봉투 구조 (캡슐화)</h3>
        <label className="muted">
          <input type="checkbox" checked={showHelp} onChange={(e) => setShowHelp(e.target.checked)} /> 설명 보기
        </label>
      </div>
      <p className="muted">패킷은 봉투 안에 봉투가 든 구조입니다. 바깥 봉투일수록 가까운 구간의 배달을 맡습니다.</p>
      {packet.layers.length > 0 && <Nested layers={packet.layers} index={0} showHelp={showHelp} onHover={setHover} />}

      <div className="detail-section">
        <h3>실제 바이트</h3>
        <span className="muted">{active ? `${active.name} 부분 표시 중` : '봉투에 마우스를 올리면 해당 부분이 표시됩니다'}</span>
      </div>
      <HexDump data={packet.data} from={active?.start ?? -1} to={active?.end ?? -1} />
    </div>
  );
}

function Nested(props: { layers: Layer[]; index: number; showHelp: boolean; onHover: (i: number | null) => void }) {
  const { layers, index, showHelp, onHover } = props;
  const layer = layers[index];
  return (
    <div className="layer" data-layer={layer.id}>
      <div onMouseEnter={() => onHover(index)} onMouseLeave={() => onHover(null)}>
        <div className="layer-head">
          <b>{layer.name}</b>
          <span className="muted">{layer.osi}</span>
        </div>
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
      {index + 1 < layers.length && <Nested layers={layers} index={index + 1} showHelp={showHelp} onHover={onHover} />}
    </div>
  );
}

function HexDump({ data, from, to }: { data: Uint8Array; from: number; to: number }) {
  const rows = [];
  const end = Math.min(data.length, HEX_LIMIT);
  for (let o = 0; o < end; o += 16) {
    const bytes = Array.from(data.subarray(o, Math.min(o + 16, end)));
    rows.push(
      <div key={o} className="hex-row">
        <span className="muted">{hex(o, 4)}</span>
        <span className="hex-bytes">
          {bytes.map((b, i) => (
            <span key={i} className={o + i >= from && o + i < to ? 'hl' : ''}>
              {hex(b)}
            </span>
          ))}
        </span>
        <span className="hex-ascii">
          {bytes.map((b, i) => (
            <span key={i} className={o + i >= from && o + i < to ? 'hl' : ''}>
              {b >= 32 && b < 127 ? String.fromCharCode(b) : '·'}
            </span>
          ))}
        </span>
      </div>,
    );
  }
  return (
    <div className="hex mono">
      {rows}
      {data.length > HEX_LIMIT && <p className="muted">처음 {HEX_LIMIT}바이트만 표시합니다 (전체 {data.length}바이트).</p>}
    </div>
  );
}
