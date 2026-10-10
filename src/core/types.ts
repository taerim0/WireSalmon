export type LayerId = 'eth' | 'arp' | 'ipv4' | 'ipv6' | 'icmp' | 'tcp' | 'udp' | 'dns' | 'dhcp' | 'http' | 'tls' | 'data';

export interface Field {
  label: string;
  value: string;
  help?: string;
}

/** 패킷을 감싸고 있는 봉투 한 겹 */
export interface Layer {
  id: LayerId;
  name: string;
  /** 접어 두었을 때 보여 줄 한 줄 요약 */
  brief: string;
  osi: string;
  role: string;
  start: number;
  end: number;
  fields: Field[];
}

export interface TcpInfo {
  seq: number;
  ack: number;
  flags: number;
  payloadLen: number;
}

export type Stage = 'open' | 'data' | 'close';

/** 진단과 시간 분해에 쓰는, 언어와 무관한 패킷 정보 */
export interface PacketInfo {
  dns?: { response: boolean; rcode: number; answers: number };
  http?: { method?: string; status?: number; reason?: string };
  tlsHello?: 'client' | 'server';
  tlsAlert?: { fatal: boolean; code: number };
  icmp?: { type: number; code: number; v6: boolean; echo?: 'request' | 'reply'; seq?: number };
  arp?: 'request' | 'reply';
  dhcp?: number;
}

export interface Packet {
  no: number;
  ts: number;
  origLen: number;
  data: Uint8Array;
  layers: Layer[];
  src: string;
  dst: string;
  srcPort?: number;
  dstPort?: number;
  /** 표에 보여 줄 대표 프로토콜 */
  proto: string;
  /** 한국어 한 줄 설명 */
  summary: string;
  flowKey: string;
  tcp?: TcpInfo;
  /** 대화 종류를 결정하는 응용 프로토콜 (DNS, HTTP, HTTPS …) */
  appLabel?: string;
  host?: string;
  /** 이 패킷에서 알게 된 IP → 이름 */
  names?: [string, string][];
  /** 주소만으로 방향을 알 수 없을 때(DHCP 등) 해석기가 직접 지정 */
  fromClient?: boolean;
  truncated?: boolean;
  info?: PacketInfo;
  flowId?: number;
  fromA?: boolean;
  stage?: Stage;
}

export interface Endpoint {
  addr: string;
  port?: number;
  label?: string;
  /** 대화가 시작될 때 알고 있던 이름. 같은 주소를 여러 사이트가 쓰기 때문에 그 시점의 이름을 붙잡아 둔다. */
  name?: string;
}

export interface TcpState {
  syn: boolean;
  synAck: boolean;
  established: boolean;
  fin: { a: boolean; b: boolean };
  rst: boolean;
  isn: { a?: number; b?: number };
  maxEnd: { a?: number; b?: number };
  /** maxEnd를 마지막으로 늘린 패킷의 시각 */
  maxEndTs: { a?: number; b?: number };
  dataBytes: number;
  retransmits: number;
  outOfOrder: number;
}

/** 두 상대가 주고받은 패킷 묶음 (하나의 "대화") */
export interface Flow {
  id: number;
  key: string;
  app: string;
  a: Endpoint;
  b: Endpoint;
  packets: Packet[];
  bytes: number;
  host?: string;
  firstTs: number;
  lastTs: number;
  tcp?: TcpState;
  /** 이 대화 직전에 상대 주소를 알아낸 DNS 조회 */
  lookup?: { name: string; ms: number; flowId: number };
}
