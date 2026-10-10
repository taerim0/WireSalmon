import { Fragment, useEffect, useRef, useState } from 'react';
import { endpointAddr, endpointName, flowGuide, flowStatus, flowTitle } from '../core/describe.ts';
import { findings, type Finding } from '../core/diagnose.ts';
import { timing } from '../core/timing.ts';
import type { Flow, Packet } from '../core/types.ts';
import type { Messages } from '../i18n/index.ts';
import { useMessages } from './locale.ts';

export const seconds = (ts: number, t0: number, L: Messages) => L.ui.seconds((ts - t0).toFixed(3));

export function Badge({ app }: { app: string }) {
  return (
    <span className="badge" data-app={app}>
      {app}
    </span>
  );
}

const FLOW_LIMIT = 500;

export function FlowList(props: { flows: Flow[]; names: Map<string, string>; t0: number; problems: Map<number, 'bad' | 'warn'>; selected: number | null; onSelect: (id: number) => void }) {
  const { flows, names, t0, problems, selected, onSelect } = props;
  const L = useMessages();
  return (
    <ul className="flow-list">
      {flows.slice(0, FLOW_LIMIT).map((flow) => (
        <li key={flow.id}>
          <button className={`flow-card ${flow.id === selected ? 'on' : ''}`} onClick={() => onSelect(flow.id)}>
            <span className="flow-card-top">
              <span className="flow-card-kind">
                <Badge app={flow.app} />
                {problems.has(flow.id) && (
                  <span className={`problem-mark ${problems.get(flow.id)}`} title={problems.get(flow.id) === 'bad' ? L.ui.problemBad : L.ui.problemWarn}>
                    {problems.get(flow.id) === 'bad' ? '✕' : '⚠'}
                  </span>
                )}
              </span>
              <span className="muted">
                {seconds(flow.firstTs, t0, L)} · {L.ui.packetCount(flow.packets.length)}
              </span>
            </span>
            <span className="flow-card-title">{flowTitle(flow, names, L)}</span>
            <span className="muted mono">
              {endpointAddr(flow.a) || flow.a.label} ↔ {endpointAddr(flow.b) || flow.b.label}
            </span>
          </button>
        </li>
      ))}
      {flows.length > FLOW_LIMIT && <li className="empty">{L.ui.tooManyFlows(FLOW_LIMIT)}</li>}
    </ul>
  );
}

const PAGE = 300;

/** 두 상대 사이에 오간 패킷을 화살표로 보여 주는 시퀀스 다이어그램 */
export function FlowView(props: { flow: Flow; names: Map<string, string>; now: number; selected: number | null; onSelect: (no: number) => void }) {
  const { flow, names, now, selected, onSelect } = props;
  const L = useMessages();
  const [limit, setLimit] = useState(PAGE);
  const shown = flow.packets.slice(0, limit);
  const start = flow.firstTs;
  return (
    <div className="flow-view">
      <div className="flow-head">
        <h2>
          <Badge app={flow.app} /> {flowTitle(flow, names, L)}
        </h2>
        <p>{flowGuide(flow, L)}</p>
        <div className="chips">
          {flowStatus(flow, L).map((chip) => (
            <span key={chip.label} className={`status ${chip.tone}`}>
              {chip.label}
            </span>
          ))}
        </div>
        <Diagnosis list={findings(flow, names, L, now)} />
        <TimingBar flow={flow} />
      </div>

      <div className="seq">
        <div className="seq-ends">
          <EndpointBox name={endpointName(flow.a, names)} addr={endpointAddr(flow.a)} role={L.flow.initiator} />
          <EndpointBox name={endpointName(flow.b, names)} addr={endpointAddr(flow.b)} role={L.flow.peer} />
        </div>
        {shown.map((p, i) => (
          <Fragment key={p.no}>
            {p.stage && p.stage !== shown[i - 1]?.stage && <div className="seq-stage">{L.flow.stages[p.stage]}</div>}
            <button className={`seq-row ${p.fromA ? 'ltr' : 'rtl'} ${p.no === selected ? 'on' : ''}`} onClick={() => onSelect(p.no)}>
              <span className="seq-time muted mono">+{seconds(p.ts, start, L)}</span>
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
            {L.ui.more((flow.packets.length - limit).toLocaleString(L.tag))}
          </button>
        )}
      </div>
    </div>
  );
}

const TONE_ICON = { ok: '✓', info: 'ℹ', warn: '⚠', bad: '✕' } as const;

/** 이 대화에서 무엇이 잘됐고 무엇이 잘못됐는지 */
function Diagnosis({ list }: { list: Finding[] }) {
  const L = useMessages();
  if (list.length === 0) return null;
  return (
    <section className="insight">
      <h3>{L.diag.heading}</h3>
      <ul className="findings">
        {list.map((finding) => (
          <li key={finding.title} className={`finding ${finding.tone}`}>
            <span className="finding-icon" aria-hidden>
              {TONE_ICON[finding.tone]}
            </span>
            <span>
              <b>{finding.title}</b>
              <span className="muted">{finding.detail}</span>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** 대화가 어느 구간에서 시간을 썼는지 막대와 목록으로 보여 준다 */
function TimingBar({ flow }: { flow: Flow }) {
  const L = useMessages();
  const m = L.timing;
  const { phases, totalMs, slowest } = timing(flow);
  if (phases.length === 0) return null;
  const sum = phases.reduce((n, phase) => n + phase.ms, 0) || 1;
  return (
    <section className="insight">
      <h3>{m.heading}</h3>
      <div className="timing-bar" aria-hidden>
        {phases.map((phase, i) => (
          <span key={i} data-kind={phase.kind} style={{ flexGrow: Math.max(phase.ms / sum, 0.02) }} />
        ))}
      </div>
      <ul className="phases">
        {phases.map((phase, i) => (
          <li key={i}>
            <span className="phase-dot" data-kind={phase.kind} />
            <span className="phase-label">{m.labels[phase.kind]}</span>
            <span className="phase-ms mono">{m.duration(phase.ms)}</span>
            <span className="muted">
              {phase.slow && <b className="slow">{m.slow}</b>}
              {phase.slow ? m.slowHint[phase.kind] : m.help[phase.kind]}
              {phase.count && phase.count > 1 ? ` (${m.measured(phase.count, m.duration(phase.min!), m.duration(phase.max!))})` : ''}
            </span>
          </li>
        ))}
      </ul>
      <p className="muted">
        {slowest ? `${m.slowest(m.labels[slowest.kind], m.duration(slowest.ms))} ` : ''}
        {m.total(m.duration(totalMs))}
      </p>
    </section>
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
  const L = useMessages();
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
        <span>{L.ui.colNo}</span>
        <span>{L.ui.colTime}</span>
        <span>{L.ui.colSrc}</span>
        <span>{L.ui.colDst}</span>
        <span>{L.ui.colKind}</span>
        <span>{L.ui.colWhat}</span>
      </div>
      <div style={{ height: packets.length * ROW, position: 'relative' }}>
        {packets.slice(first, last).map((p, i) => (
          <button key={p.no} className={`prow ${p.no === selected ? 'on' : ''}`} style={{ top: (first + i) * ROW }} onClick={() => onSelect(p)}>
            <span className="mono">{p.no}</span>
            <span className="mono">{seconds(p.ts, t0, L)}</span>
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
