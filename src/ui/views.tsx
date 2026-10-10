import { Fragment, useEffect, useRef, useState } from 'react';
import { endpointAddr, endpointName, flowGuide, flowStatus, flowTitle, STAGE_TITLES } from '../core/describe.ts';
import type { Flow, Packet } from '../core/types.ts';

export const seconds = (ts: number, t0: number) => `${(ts - t0).toFixed(3)}초`;

export function Badge({ app }: { app: string }) {
  return (
    <span className="badge" data-app={app}>
      {app}
    </span>
  );
}

const FLOW_LIMIT = 500;

export function FlowList(props: { flows: Flow[]; names: Map<string, string>; t0: number; selected: number | null; onSelect: (id: number) => void }) {
  const { flows, names, t0, selected, onSelect } = props;
  return (
    <ul className="flow-list">
      {flows.slice(0, FLOW_LIMIT).map((flow) => (
        <li key={flow.id}>
          <button className={`flow-card ${flow.id === selected ? 'on' : ''}`} onClick={() => onSelect(flow.id)}>
            <span className="flow-card-top">
              <Badge app={flow.app} />
              <span className="muted">
                {seconds(flow.firstTs, t0)} · {flow.packets.length}개
              </span>
            </span>
            <span className="flow-card-title">{flowTitle(flow, names)}</span>
            <span className="muted mono">
              {endpointAddr(flow.a) || flow.a.label} ↔ {endpointAddr(flow.b) || flow.b.label}
            </span>
          </button>
        </li>
      ))}
      {flows.length > FLOW_LIMIT && <li className="empty">대화가 많아 처음 {FLOW_LIMIT}개만 보여 드립니다. 위에서 검색해 좁혀 보세요.</li>}
    </ul>
  );
}

const PAGE = 300;

/** 두 상대 사이에 오간 패킷을 화살표로 보여 주는 시퀀스 다이어그램 */
export function FlowView(props: { flow: Flow; names: Map<string, string>; selected: number | null; onSelect: (no: number) => void }) {
  const { flow, names, selected, onSelect } = props;
  const [limit, setLimit] = useState(PAGE);
  const shown = flow.packets.slice(0, limit);
  const start = flow.firstTs;
  return (
    <div className="flow-view">
      <div className="flow-head">
        <h2>
          <Badge app={flow.app} /> {flowTitle(flow, names)}
        </h2>
        <p>{flowGuide(flow)}</p>
        <div className="chips">
          {flowStatus(flow).map((chip) => (
            <span key={chip.label} className={`status ${chip.tone}`}>
              {chip.label}
            </span>
          ))}
        </div>
      </div>

      <div className="seq">
        <div className="seq-ends">
          <EndpointBox name={endpointName(flow.a, names)} addr={endpointAddr(flow.a)} role="먼저 말을 건 쪽" />
          <EndpointBox name={endpointName(flow.b, names)} addr={endpointAddr(flow.b)} role="상대" />
        </div>
        {shown.map((p, i) => (
          <Fragment key={p.no}>
            {p.stage && p.stage !== shown[i - 1]?.stage && <div className="seq-stage">{STAGE_TITLES[p.stage]}</div>}
            <button className={`seq-row ${p.fromA ? 'ltr' : 'rtl'} ${p.no === selected ? 'on' : ''}`} onClick={() => onSelect(p.no)}>
              <span className="seq-time muted mono">+{(p.ts - start).toFixed(3)}초</span>
              <span className="seq-arrow">
                <span className="seq-label">
                  <Badge app={p.proto} /> {p.summary}
                </span>
                <span className="seq-line" />
              </span>
            </button>
          </Fragment>
        ))}
        {flow.packets.length > limit && (
          <button className="btn more" onClick={() => setLimit(limit + PAGE)}>
            {(flow.packets.length - limit).toLocaleString()}개 더 있음 — 더 보기
          </button>
        )}
      </div>
    </div>
  );
}

function EndpointBox({ name, addr, role }: { name: string; addr: string; role: string }) {
  return (
    <div className="seq-end">
      <span className="muted">{role}</span>
      <b>{name}</b>
      {addr && addr !== name && <span className="muted mono">{addr}</span>}
    </div>
  );
}

const ROW = 30;

/** Wireshark식 전체 패킷 목록. 보이는 줄만 그린다. */
export function PacketTable(props: { packets: Packet[]; t0: number; selected: number | null; onSelect: (p: Packet) => void }) {
  const { packets, t0, selected, onSelect } = props;
  const ref = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  const [height, setHeight] = useState(600);
  useEffect(() => {
    const el = ref.current!;
    const observer = new ResizeObserver(() => setHeight(el.clientHeight));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  const first = Math.max(0, Math.floor(top / ROW) - 10);
  const last = Math.min(packets.length, first + Math.ceil(height / ROW) + 20);
  return (
    <div className="ptable" ref={ref} onScroll={(e) => setTop(e.currentTarget.scrollTop)}>
      <div className="prow phead">
        <span>번호</span>
        <span>시간</span>
        <span>보낸 곳</span>
        <span>받는 곳</span>
        <span>종류</span>
        <span>무슨 일인가요</span>
      </div>
      <div style={{ height: packets.length * ROW, position: 'relative' }}>
        {packets.slice(first, last).map((p, i) => (
          <button key={p.no} className={`prow ${p.no === selected ? 'on' : ''}`} style={{ top: (first + i) * ROW }} onClick={() => onSelect(p)}>
            <span className="mono">{p.no}</span>
            <span className="mono">{seconds(p.ts, t0)}</span>
            <span className="mono">{p.src}</span>
            <span className="mono">{p.dst}</span>
            <span>
              <Badge app={p.proto} />
            </span>
            <span>{p.summary}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
