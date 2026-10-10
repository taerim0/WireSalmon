# 🐟 WireSalmon

[English](README.md) | **한국어**

사람을 위한 Wireshark — 패킷을 대화 단위로 묶어 쉬운 말로 설명해 주는 학습용 패킷 분석기입니다.

Wireshark는 패킷을 한 줄씩 보여 줍니다. 처음 배우는 사람이 궁금한 건 "방금 무슨 일이 일어났나"입니다. WireSalmon은 같은 캡처를 읽어서 그 질문에 먼저 답합니다.

> 설명은 현재 한국어로만 제공됩니다. 영어는 추가할 예정입니다.

## 기능

- **패킷 줄 대신 대화** — 패킷을 "이름 찾기: example.com", "암호화된 웹 통신: example.com" 같은 대화로 묶어 보여 줍니다.
- **시퀀스 다이어그램** — 대화마다 두 상대 사이의 화살표로 그립니다. TCP는 연결 맺기, 데이터 주고받기, 연결 끊기로 구간을 나눕니다.
- **쉬운 말 설명** — `[SYN, ACK] Seq=0 Ack=1` 대신 *"② 연결 수락 — '좋아요, 저도 준비됐어요'"* 라고 보여 줍니다.
- **봉투 구조** — 이더넷 → IP → TCP → HTTP를 겹친 봉투로 보여 주고 필드마다 설명을 붙입니다. 봉투에 마우스를 올리면 실제 바이트에서 해당 부분이 표시됩니다.
- **세 가지 시작 방법** — 내장 샘플, `.pcap` / `.pcapng` 파일(끌어다 놓기), 실시간 캡처.

파일은 브라우저 안에서만 해석합니다. 어디에도 업로드하지 않습니다.

## 지원 프로토콜

자세히 해석: Ethernet(VLAN), ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, mDNS, LLMNR, DHCP, HTTP/1.x, TLS(핸드셰이크 메시지와 접속 사이트 이름).

그 밖의 트래픽은 잘 알려진 포트 번호로 이름만 붙입니다(SSH, NTP, SSDP, QUIC 등).

## 시작하기

Node.js 24가 필요합니다.

```bash
npm install
npm run dev
```

`http://localhost:5173`을 열고 **샘플 열기**를 누르세요.

### 실시간 캡처

브라우저는 네트워크 카드를 직접 읽을 수 없습니다. 그래서 실시간 캡처는 `dumpcap`을 실행해 WebSocket으로 패킷을 흘려보내는 작은 로컬 헬퍼를 거칩니다.

- [Wireshark](https://www.wireshark.org/)를 설치하세요(Windows는 Npcap 포함). `dumpcap`이 함께 설치됩니다.
- 캡처하려는 컴퓨터에서 `npm run dev`로 실행하세요. 정적으로 호스팅한 사본에서는 실시간 캡처를 쓸 수 없습니다.
- `dumpcap`이 기본 위치에 없으면 `WIRESALMON_DUMPCAP` 환경 변수에 전체 경로를 넣으세요.

캡처 소켓은 `localhost`의 같은 페이지에서 온 연결만 받습니다. 패킷이 50,000개에 이르면 캡처가 자동으로 멈춥니다.

Windows 11에서 확인했습니다. Linux와 macOS의 일반적인 `dumpcap` 위치도 찾도록 되어 있지만 아직 테스트하지 못했습니다.

## 명령어

| 명령 | 하는 일 |
|---|---|
| `npm run dev` | 개발 서버 실행 (실시간 캡처 헬퍼 포함) |
| `npm run build` | 타입 검사 후 정적 사이트를 `dist/`에 빌드 |
| `npm run preview` | 빌드한 사이트 실행 (실시간 캡처 헬퍼 포함) |
| `npm test` | 코어 테스트 실행 |

## 폴더 구조

```
src/core/     캡처 해석기(pcap, pcapng), 프로토콜 해석, 대화 묶기, 샘플 생성
src/ui/       React 화면
server/       실시간 캡처 헬퍼 (dumpcap → WebSocket)
test/         코어 테스트
```

## 기여

커밋 규칙은 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 라이선스

[MIT](LICENSE)
