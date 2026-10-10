import { useEffect, useMemo, useRef, useState } from 'react';
import { flowTitle } from '../core/describe.ts';
import { findings, problemOf } from '../core/diagnose.ts';
import { CaptureError, CaptureReader } from '../core/reader.ts';
import { SAMPLES } from '../core/sample.ts';
import { Session } from '../core/session.ts';
import type { Flow } from '../core/types.ts';
import { LOCALE_NAMES, LOCALES, type Locale, type Messages } from '../i18n/index.ts';
import { PacketDetail } from './Detail.tsx';
import { initialLocale, LocaleContext, saveLocale, useMessages } from './locale.ts';
import { FlowList, FlowView, PacketTable } from './views.tsx';

interface CaptureInterface {
  id: string;
  name: string;
  address: string | null;
}

/** 어디서 온 캡처인지. 언어를 바꿔도 다시 그릴 수 있게 문장이 아니라 재료로 들고 있는다. */
type Source = { kind: 'sample'; id: string } | { kind: 'file' | 'live'; name: string };

type AppError = { key: 'format' | 'corrupt' | 'read' | 'liveParse' | 'liveConnect' | 'dumpcapMissing' | 'liveLimit' } | { key: 'captureStopped'; detail: string };

/** 실시간 캡처가 브라우저를 멈추게 하지 않도록 두는 상한 */
const MAX_LIVE_PACKETS = 50000;

function errorText(error: AppError, L: Messages): string {
  if (error.key === 'captureStopped') return L.errors.captureStopped(error.detail);
  if (error.key === 'liveLimit') return L.errors.liveLimit(MAX_LIVE_PACKETS.toLocaleString(L.tag));
  return L.errors[error.key];
}

function sourceText(source: Source, L: Messages): string {
  if (source.kind === 'sample') return L.ui.sourceSample(L.samples[source.id]?.title ?? source.id);
  return source.kind === 'file' ? L.ui.sourceFile(source.name) : L.ui.sourceLive(source.name);
}

export function App() {
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const L = LOCALES[locale];
  const sessionRef = useRef<Session | null>(null);
  const [version, setVersion] = useState(0);
  const dirty = useRef(false);
  const [source, setSource] = useState<Source | null>(null);
  const [error, setError] = useState<AppError | null>(null);
  const [flowId, setFlowId] = useState<number | null>(null);
  const [packetNo, setPacketNo] = useState<number | null>(null);
  const [tab, setTab] = useState<'flow' | 'packets'>('flow');
  const [query, setQuery] = useState('');
  const [appFilter, setAppFilter] = useState<string | null>(null);
  const [problemsOnly, setProblemsOnly] = useState(false);

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

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  function changeLocale(next: Locale) {
    saveLocale(next);
    setLocale(next);
    // 이미 열어 둔 캡처도 새 언어로 다시 해석한다
    sessionRef.current?.relocalize(LOCALES[next]);
    setVersion((v) => v + 1);
  }

  function reset(session: Session, from: Source) {
    socket.current?.close();
    sessionRef.current = session;
    setSource(from);
    setError(null);
    setFlowId(null);
    setPacketNo(null);
    setQuery('');
    setAppFilter(null);
    setProblemsOnly(false);
    setVersion((v) => v + 1);
  }

  function loadBytes(bytes: Uint8Array, from: Source) {
    const session = new Session(L);
    let failure: AppError | null = null;
    try {
      for (const raw of new CaptureReader().push(bytes)) session.add(raw);
    } catch (e) {
      failure = { key: e instanceof CaptureError ? e.code : 'read' };
    }
    if (failure && session.packets.length === 0) {
      setError(failure);
      return;
    }
    reset(session, from);
    setError(failure);
  }

  function openSample(id: string) {
    const sample = SAMPLES.find((s) => s.id === id);
    if (sample) loadBytes(sample.build(L.sampleBodyLine), { kind: 'sample', id });
  }

  async function openFile(file: File | undefined) {
    if (file) loadBytes(new Uint8Array(await file.arrayBuffer()), { kind: 'file', name: file.name });
  }

  function startLive() {
    const target = interfaces?.find((i) => i.id === iface);
    if (!target) return;
    const session = new Session(L);
    const reader = new CaptureReader();
    reset(session, { kind: 'live', name: target.name });
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/capture?iface=${target.id}`);
    ws.binaryType = 'arraybuffer';
    socket.current = ws;
    setRunning(true);
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        const message = JSON.parse(ev.data) as { error?: string; detail?: string };
        if (message.error === 'capture-stopped') setError({ key: 'captureStopped', detail: message.detail ?? '' });
        else if (message.error) setError({ key: 'dumpcapMissing' });
        return;
      }
      try {
        for (const raw of reader.push(new Uint8Array(ev.data as ArrayBuffer))) session.add(raw);
      } catch {
        setError({ key: 'liveParse' });
        ws.close();
      }
      dirty.current = true;
      if (session.packets.length >= MAX_LIVE_PACKETS) {
        setError({ key: 'liveLimit' });
        ws.close();
      }
    };
    ws.onerror = () => setError({ key: 'liveConnect' });
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

  /** 문제가 있는 대화와 그 심각도 */
  const problems = useMemo(() => {
    const found = new Map<number, 'bad' | 'warn'>();
    if (!session) return found;
    for (const flow of session.flows) {
      const problem = problemOf(findings(flow, session.names, L, session.lastTs));
      if (problem) found.set(flow.id, problem);
    }
    return found;
  }, [session, version, L]);

  const flows = useMemo(() => {
    if (!session) return [];
    const q = query.trim().toLowerCase();
    const matches = (flow: Flow) =>
      (!problemsOnly || problems.has(flow.id)) &&
      (!appFilter || flow.app === appFilter) &&
      (!q || `${flow.app} ${flowTitle(flow, session.names, L)} ${flow.a.addr} ${flow.b.addr} ${flow.a.port ?? ''} ${flow.b.port ?? ''}`.toLowerCase().includes(q));
    return session.flows.filter(matches);
  }, [session, version, query, appFilter, problemsOnly, problems, L]);

  const packets = useMemo(() => {
    if (!session) return [];
    if (!query.trim() && !appFilter && !problemsOnly) return session.packets;
    const visible = new Set(flows.map((f) => f.id));
    return session.packets.filter((p) => visible.has(p.flowId!));
  }, [session, version, flows, query, appFilter, problemsOnly]);

  const flow = flows.find((f) => f.id === flowId) ?? flows[0] ?? null;
  const packet = packetNo === null ? null : (session?.packets[packetNo - 1] ?? null);
  const count = (n: number) => n.toLocaleString(L.tag);

  return (
    <LocaleContext.Provider value={L}>
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
          <select
            id="sample-menu"
            className="btn"
            value=""
            onChange={(e) => openSample(e.target.value)}
            aria-label={L.ui.openSample}
          >
            <option value="" disabled>
              {L.ui.openSample}
            </option>
            {SAMPLES.map((s) => (
              <option key={s.id} value={s.id}>
                {L.samples[s.id]?.title ?? s.id}
              </option>
            ))}
          </select>
          <button className="btn" onClick={() => fileInput.current?.click()}>
            {L.ui.openFile}
          </button>
          <input ref={fileInput} type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => void openFile(e.target.files?.[0])} />
          <span className="live">
            <select id="capture-interface" value={iface} onChange={(e) => setIface(e.target.value)} disabled={!interfaces || running} aria-label={L.ui.interfaceLabel}>
              {interfaces ? (
                interfaces.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.name}
                    {i.address ? ` (${i.address})` : ''}
                  </option>
                ))
              ) : (
                <option>{L.ui.liveUnavailable}</option>
              )}
            </select>
            {running ? (
              <button className="btn danger" onClick={() => socket.current?.close()}>
                {L.ui.liveStop}
              </button>
            ) : (
              <button className="btn primary" onClick={startLive} disabled={!interfaces?.length} title={interfaces ? '' : L.ui.liveHint}>
                {L.ui.liveStart}
              </button>
            )}
          </span>
          <span className="source">
            {running && <span className="dot" />}
            {source && sourceText(source, L)}
            {session ? ` · ${L.ui.counts(count(session.packets.length), count(session.flows.length))}` : ''}
          </span>
          <select id="language" className="language" value={locale} onChange={(e) => changeLocale(e.target.value as Locale)} aria-label={L.ui.language}>
            {(Object.keys(LOCALES) as Locale[]).map((code) => (
              <option key={code} value={code}>
                {LOCALE_NAMES[code]}
              </option>
            ))}
          </select>
        </header>

        {error && <div className="error">{errorText(error, L)}</div>}

        {!session ? (
          <Welcome onSample={openSample} liveAvailable={!!interfaces?.length} />
        ) : (
          <main className="panes">
            <aside className="pane flows">
              <div className="filters">
                <input id="flow-search" type="search" placeholder={L.ui.search} value={query} onChange={(e) => setQuery(e.target.value)} />
                <div className="chips">
                  {problems.size > 0 && (
                    <button className={`chip problem ${problemsOnly ? 'on' : ''}`} onClick={() => setProblemsOnly(!problemsOnly)}>
                      ⚠ {L.ui.problems(problems.size)}
                    </button>
                  )}
                  {apps.map(([app, n]) => (
                    <button key={app} className={`chip ${appFilter === app ? 'on' : ''}`} onClick={() => setAppFilter(appFilter === app ? null : app)}>
                      {app} {n}
                    </button>
                  ))}
                </div>
              </div>
              <FlowList flows={flows} names={session.names} t0={session.t0} problems={problems} selected={flow?.id ?? null} onSelect={(id) => (setFlowId(id), setTab('flow'))} />
            </aside>

            <section className="pane center">
              <nav className="tabs">
                <button className={tab === 'flow' ? 'on' : ''} onClick={() => setTab('flow')}>
                  {L.ui.tabFlow}
                </button>
                <button className={tab === 'packets' ? 'on' : ''} onClick={() => setTab('packets')}>
                  {L.ui.tabPackets(count(packets.length))}
                </button>
              </nav>
              {tab === 'flow' ? (
                flow ? (
                  <FlowView key={flow.id} flow={flow} names={session.names} now={session.lastTs} selected={packetNo} onSelect={setPacketNo} />
                ) : (
                  <p className="empty">{running ? L.ui.waiting : L.ui.noMatch}</p>
                )
              ) : (
                <PacketTable packets={packets} t0={session.t0} selected={packetNo} onSelect={(p) => (setPacketNo(p.no), setFlowId(p.flowId ?? null))} />
              )}
            </section>

            <aside className="pane detail">{packet ? <PacketDetail key={packet.no} packet={packet} t0={session.t0} /> : <p className="empty">{L.ui.pickPacket}</p>}</aside>
          </main>
        )}
      </div>
    </LocaleContext.Provider>
  );
}

function Welcome({ onSample, liveAvailable }: { onSample: (id: string) => void; liveAvailable: boolean }) {
  const L = useMessages();
  const { ui } = L;
  return (
    <div className="welcome">
      <h2>{ui.welcomeTitle}</h2>
      <p>{ui.welcomeIntro}</p>
      <p className="privacy">{ui.privacy}</p>
      <ol>
        <li>
          <b>{ui.step1Title}</b> — {ui.step1Body}
          <div className="sample-cards">
            {SAMPLES.map((s) => (
              <button key={s.id} className="sample-card" onClick={() => onSample(s.id)}>
                <b>{L.samples[s.id]?.title ?? s.id}</b>
                <span className="muted">{L.samples[s.id]?.description}</span>
              </button>
            ))}
          </div>
        </li>
        <li>
          <b>{ui.step2Title}</b> — {ui.step2Body}
        </li>
        <li>
          <b>{ui.step3Title}</b> — {liveAvailable ? ui.step3On : ui.step3Off}
        </li>
      </ol>
    </div>
  );
}
