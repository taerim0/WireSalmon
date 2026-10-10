# 🐟 WireSalmon

**English** | [한국어](README.ko.md)

Wireshark for humans — a learning-focused packet analyzer that groups packets into conversations and explains them in plain language.

Wireshark shows you one packet per line. A beginner wants to know *what just happened*. WireSalmon reads the same captures and answers that question first.

> The explanations are currently written in Korean only. English is planned.

## What it does

- **Conversations, not packet lines** — packets are grouped into exchanges such as "name lookup: example.com" or "encrypted web traffic: example.com".
- **Sequence diagram** — each conversation is drawn as arrows between the two sides. TCP is split into opening the connection, exchanging data and closing it.
- **Plain-language explanations** — `[SYN, ACK] Seq=0 Ack=1` becomes *"② connection accepted — 'sure, I'm ready too'"*.
- **Envelope view** — Ethernet → IP → TCP → HTTP shown as nested envelopes, with a description for every field. Hover an envelope to highlight its bytes in the hex dump.
- **Three ways in** — a built-in sample, `.pcap` / `.pcapng` files (drag and drop), or live capture.

Files are parsed inside the browser. Nothing is uploaded.

## Supported protocols

Dissected in detail: Ethernet (VLAN), ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, mDNS, LLMNR, DHCP, HTTP/1.x, TLS (handshake messages and server name).

Other traffic is labelled by well-known port (SSH, NTP, SSDP, QUIC, …) without deeper decoding.

## Getting started

Requires Node.js 24.

```bash
npm install
npm run dev
```

Then open `http://localhost:5173` and click **샘플 열기** (open sample).

### Live capture

A browser cannot read a network card, so live capture goes through a small local helper that runs `dumpcap` and streams packets to the page over a WebSocket.

- Install [Wireshark](https://www.wireshark.org/) (on Windows, include Npcap). `dumpcap` ships with it.
- Run `npm run dev` on the machine you want to capture on. Live capture is unavailable on a statically hosted copy.
- If `dumpcap` is somewhere unusual, set `WIRESALMON_DUMPCAP` to its full path.

The capture socket only accepts connections from the same page on `localhost`. Capture stops automatically at 50,000 packets.

Tested on Windows 11. The helper also looks for `dumpcap` in the usual Linux and macOS locations, but those have not been tested yet.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Dev server with the live capture helper |
| `npm run build` | Type-check and build the static site into `dist/` |
| `npm run preview` | Serve the built site, with the live capture helper |
| `npm test` | Run the core tests |

## Project layout

```
src/core/     capture reader (pcap, pcapng), dissectors, conversation grouping, sample generator
src/ui/       React screens
server/       live capture helper (dumpcap → WebSocket)
test/         core tests
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit conventions.

## License

[MIT](LICENSE)
