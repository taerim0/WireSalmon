import { useEffect, useMemo, useRef, useState } from 'react';
import { flowTitle } from '../core/describe.ts';
import { CaptureReader } from '../core/reader.ts';
import { SAMPLES } from '../core/sample.ts';
import { Session } from '../core/session.ts';
import type { Flow } from '../core/types.ts';
import { PacketDetail } from './Detail.tsx';
import { FlowList, FlowView, PacketTable } from './views.tsx';

interface CaptureInterface {
  id: string;
  name: string;
  address: string | null;
}

/** 실시간 캡처가 브라우저를 멈추게 하지 않도록 두는 상한 */
const MAX_LIVE_PACKETS = 50000;

export function App() {
  const sessionRef = useRef<Session | null>(null);
  const [version, setVersion] = useState(0);
  const dirty = useRef(false);
  const [source, setSource] = useState('');
  const [error, setError] = useState('');
  const [flowId, setFlowId] = useState<number | null>(null);
  const [packetNo, setPacketNo] = useState<number | null>(null);
  const [tab, setTab] = useState<'flow' | 'packets'>('flow');
  const [query, setQuery] = useState('');
  const [appFilter, setAppFilter] = useState<string | null>(null);

  const [interfaces, setInterfaces] = useState<CaptureInterface[] | null>(null);
  const [iface, setIface] = useState('');
  const [running, setRunning] = useState(false);
  const socket = useRef<WebSocket | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    fetch('/api/interfaces')
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((body: { interfaces: CaptureInterface[] }) => {
        setInterfaces(body.interfaces);
        setIface(body.interfaces[0]?.id ?? '');
      })
      .catch(() => setInterfaces(null));
  }, []);

  // 실시간 캡처 중에는 패킷마다 다시 그리지 않고 일정 간격으로 모아서 그린다
  useEffect(() => {
    const timer = setInterval(() => {
      if (!dirty.current) return;
      dirty.current = false;
      setVersion((v) => v + 1);
    }, 300);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => () => socket.current?.close(), []);

  function reset(session: Session, label: string) {
    socket.current?.close();
    sessionRef.current = session;
    setSource(label);
    setError('');
    setFlowId(null);
    setPacketNo(null);
    setQuery('');
    setAppFilter(null);
    setVersion((v) => v + 1);
  }

  function loadBytes(bytes: Uint8Array, label: string) {
    const session = new Session();
    try {
      for (const raw of new CaptureReader().push(bytes)) session.add(raw);
    } catch (e) {
      setError(e instanceof Error ? e.message : '파일을 읽지 못했습니다.');
      if (session.packets.length === 0) return;
    }
    reset(session, label);
  }

  async function openFile(file: File | undefined) {
    if (file) loadBytes(new Uint8Array(await file.arrayBuffer()), `파일: ${file.name}`);
  }

  function startLive() {
    const target = interfaces?.find((i) => i.id === iface);
    if (!target) return;
    const session = new Session();
    const reader = new CaptureReader();
    reset(session, `실시간: ${target.name}`);
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/capture?iface=${target.id}`);
    ws.binaryType = 'arraybuffer';
    socket.current = ws;
    setRunning(true);
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        setError((JSON.parse(ev.data) as { error?: string }).error ?? '');
        return;
      }
      try {
        for (const raw of reader.push(new Uint8Array(ev.data as ArrayBuffer))) session.add(raw);
      } catch {
        setError('캡처 데이터를 해석하지 못했습니다.');
        ws.close();
      }
      dirty.current = true;
      if (session.packets.length >= MAX_LIVE_PACKETS) {
        setError(`패킷이 ${MAX_LIVE_PACKETS.toLocaleString()}개에 도달해 캡처를 자동으로 멈췄습니다.`);
        ws.close();
      }
    };
    ws.onerror = () => setError('캡처 서버에 연결하지 못했습니다.');
    ws.onclose = () => {
      if (socket.current === ws) {
        socket.current = null;
        setRunning(false);
      }
    };
  }

  const session = sessionRef.current;

  const apps = useMemo(() => {
    const counts = new Map<string, number>();
    for (const flow of session?.flows ?? []) counts.set(flow.app, (counts.get(flow.app) ?? 0) + 1);
    return [...counts].sort((a, b) => b[1] - a[1]);
  }, [session, version]);

  const flows = useMemo(() => {
    if (!session) return [];
    const q = query.trim().toLowerCase();
    const matches = (flow: Flow) =>
      (!appFilter || flow.app === appFilter) &&
      (!q || `${flow.app} ${flowTitle(flow, session.names)} ${flow.a.addr} ${flow.b.addr} ${flow.a.port ?? ''} ${flow.b.port ?? ''}`.toLowerCase().includes(q));
    return session.flows.filter(matches);
  }, [session, version, query, appFilter]);

  const packets = useMemo(() => {
    if (!session) return [];
    if (!query.trim() && !appFilter) return session.packets;
    const visible = new Set(flows.map((f) => f.id));
    return session.packets.filter((p) => visible.has(p.flowId!));
  }, [session, version, flows, query, appFilter]);

  const flow = flows.find((f) => f.id === flowId) ?? flows[0] ?? null;
  const packet = packetNo === null ? null : (session?.packets[packetNo - 1] ?? null);

  const liveControls = (
    <span className="live">
      <select value={iface} onChange={(e) => setIface(e.target.value)} disabled={!interfaces || running} aria-label="캡처할 네트워크">
        {interfaces ? (
          interfaces.map((i) => (
            <option key={i.id} value={i.id}>
              {i.name}
              {i.address ? ` (${i.address})` : ''}
            </option>
          ))
        ) : (
          <option>실시간 캡처 사용 불가</option>
        )}
      </select>
      {running ? (
        <button className="btn danger" onClick={() => socket.current?.close()}>
          ■ 캡처 멈춤
        </button>
      ) : (
        <button className="btn primary" onClick={startLive} disabled={!interfaces?.length} title={interfaces ? '' : '내 컴퓨터에서 npm run dev로 실행하고 Wireshark(Npcap)가 설치되어 있어야 합니다.'}>
          ● 실시간 캡처
        </button>
      )}
    </span>
  );

  return (
    <div
      className="app"
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault();
        void openFile(e.dataTransfer.files[0]);
      }}
    >
      <header className="topbar">
        <h1>
          <span aria-hidden>🐟</span> WireSalmon
        </h1>
        <button className="btn" onClick={() => loadBytes(SAMPLES[0].build(), `샘플: ${SAMPLES[0].title}`)}>
          샘플 열기
        </button>
        <button className="btn" onClick={() => fileInput.current?.click()}>
          파일 열기
        </button>
        <input ref={fileInput} type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => void openFile(e.target.files?.[0])} />
        {liveControls}
        <span className="source">
          {running && <span className="dot" />}
          {source}
          {session ? ` · 패킷 ${session.packets.length.toLocaleString()}개 · 대화 ${session.flows.length.toLocaleString()}개` : ''}
        </span>
      </header>

      {error && <div className="error">{error}</div>}

      {!session ? (
        <Welcome onSample={() => loadBytes(SAMPLES[0].build(), `샘플: ${SAMPLES[0].title}`)} liveAvailable={!!interfaces?.length} />
      ) : (
        <main className="panes">
          <aside className="pane flows">
            <div className="filters">
              <input type="search" placeholder="이름, 주소, 포트로 찾기" value={query} onChange={(e) => setQuery(e.target.value)} />
              <div className="chips">
                {apps.map(([app, count]) => (
                  <button key={app} className={`chip ${appFilter === app ? 'on' : ''}`} onClick={() => setAppFilter(appFilter === app ? null : app)}>
                    {app} {count}
                  </button>
                ))}
              </div>
            </div>
            <FlowList flows={flows} names={session.names} t0={session.t0} selected={flow?.id ?? null} onSelect={(id) => (setFlowId(id), setTab('flow'))} />
          </aside>

          <section className="pane center">
            <nav className="tabs">
              <button className={tab === 'flow' ? 'on' : ''} onClick={() => setTab('flow')}>
                대화 흐름
              </button>
              <button className={tab === 'packets' ? 'on' : ''} onClick={() => setTab('packets')}>
                전체 패킷 ({packets.length.toLocaleString()})
              </button>
            </nav>
            {tab === 'flow' ? (
              flow ? (
                <FlowView key={flow.id} flow={flow} names={session.names} selected={packetNo} onSelect={setPacketNo} />
              ) : (
                <p className="empty">{running ? '패킷을 기다리는 중입니다. 웹사이트를 하나 열어 보세요.' : '조건에 맞는 대화가 없습니다.'}</p>
              )
            ) : (
              <PacketTable packets={packets} t0={session.t0} selected={packetNo} onSelect={(p) => (setPacketNo(p.no), setFlowId(p.flowId ?? null))} />
            )}
          </section>

          <aside className="pane detail">
            {packet ? <PacketDetail key={packet.no} packet={packet} t0={session.t0} /> : <p className="empty">패킷을 누르면 여기에 봉투를 한 겹씩 벗겨서 보여 드립니다.</p>}
          </aside>
        </main>
      )}
    </div>
  );
}

function Welcome({ onSample, liveAvailable }: { onSample: () => void; liveAvailable: boolean }) {
  return (
    <div className="welcome">
      <h2>패킷을 한국어로 읽어 보세요</h2>
      <p>
        WireSalmon은 네트워크를 오가는 패킷을 <b>누가 누구와 무슨 대화를 했는지</b>로 묶어서 보여 주는 학습용 도구입니다.
      </p>
      <ol>
        <li>
          <b>샘플로 시작하기</b> — 와이파이에 접속해 웹사이트를 여는 동안 일어나는 일을 순서대로 따라가 봅니다.
          <br />
          <button className="btn primary" onClick={onSample}>
            샘플 열기
          </button>
        </li>
        <li>
          <b>캡처 파일 열기</b> — Wireshark나 tcpdump로 저장한 .pcap / .pcapng 파일을 이 창에 끌어다 놓으세요. 파일은 브라우저 안에서만 읽습니다.
        </li>
        <li>
          <b>실시간 캡처</b> — {liveAvailable ? '위에서 네트워크(보통 Wi-Fi 또는 이더넷)를 고르고 "실시간 캡처"를 누른 뒤 웹사이트를 열어 보세요.' : '내 컴퓨터에서 npm run dev로 실행하고 Wireshark(Npcap 포함)가 설치되어 있으면 사용할 수 있습니다.'}
        </li>
      </ol>
    </div>
  );
}
