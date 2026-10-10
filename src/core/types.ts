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
  flowId?: number;
  fromA?: boolean;
  stage?: Stage;
}

export interface Endpoint {
  addr: string;
  port?: number;
  label?: string;
}

export interface TcpState {
  syn: boolean;
  synAck: boolean;
  established: boolean;
  fin: { a: boolean; b: boolean };
  rst: boolean;
  isn: { a?: number; b?: number };
  maxEnd: { a?: number; b?: number };
  dataBytes: number;
  retransmits: number;
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
}
