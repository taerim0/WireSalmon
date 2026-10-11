# 🐟 WireSalmon

**English** | [한국어](README.ko.md)

**Try it: <https://taerim0.github.io/WireSalmon/>** (sample and file viewing; live capture needs a local run)

Wireshark for humans — a learning-focused packet analyzer that groups packets into conversations and explains them in plain language.

Wireshark shows you one packet per line. A beginner wants to know *what just happened*. WireSalmon reads the same captures and answers that question first.

## What it does

- **Conversations, not packet lines** — packets are grouped into exchanges such as "name lookup: example.com" or "encrypted web traffic: example.com".
- **Sequence diagram** — each conversation is drawn as arrows between the two sides. TCP is split into opening the connection, exchanging data and closing it.
- **Plain-language explanations** — `[SYN, ACK] Seq=0 Ack=1` becomes *"② connection accepted — 'sure, I'm ready too'"*.
- **Diagnosis** — each conversation says what went wrong and the usual causes: connection refused, no answer, an abrupt reset, resent data, a name that does not exist, a DNS server that stays silent, HTTP errors, unanswered pings. Conversations with problems are marked in the list and can be filtered.
- **Where the time went** — a conversation is split into name lookup, connecting, encryption hello, waiting for the server and receiving the response, with the slow part pointed out.
- **HTTP messages** — for unencrypted HTTP, pieces that arrived in separate packets are joined into whole requests and responses, with links back to the packets that carried the headers and the body. Handles out-of-order and resent pieces, Content-Length and chunked bodies, and says so when a body is incomplete. Compressed bodies are not decoded.
- **Envelope view** — Ethernet → IP → TCP → HTTP shown as nested envelopes, with a description for every field. Hover an envelope to highlight its bytes in the hex dump.
- **Korean and English** — switch languages from the top bar at any time, even with a capture open. The choice is remembered, and the first visit follows the browser language.
- **Three ways in** — built-in samples (one where everything works, one where things go wrong), `.pcap` / `.pcapng` files (drag and drop), or live capture.

Files are parsed inside the browser. Nothing is uploaded. See [Privacy](#privacy).

## Supported protocols

Dissected in detail: Ethernet (VLAN), ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, mDNS, LLMNR, DHCP, HTTP/1.x, TLS (handshake messages and server name).

Other traffic is labelled by well-known port (SSH, NTP, SSDP, QUIC, …) without deeper decoding.

## Getting started

Requires Node.js 24.

```bash
npm install
npm run dev
```

Then open `http://localhost:5173` and pick a sample.

### Live capture

A browser cannot read a network card, so live capture goes through a small local helper that runs `dumpcap` and streams packets to the page over a WebSocket.

- Install [Wireshark](https://www.wireshark.org/) (on Windows, include Npcap). `dumpcap` ships with it.
- Run `npm run dev` on the machine you want to capture on. Live capture is unavailable on a statically hosted copy.
- If `dumpcap` is somewhere unusual, set `WIRESALMON_DUMPCAP` to its full path.

The capture socket only accepts connections from the same page on `localhost`. Capture stops automatically at 50,000 packets.

Tested on Windows 11. The helper also looks for `dumpcap` in the usual Linux and macOS locations, but those have not been tested yet.

## Privacy

Captures can hold passwords, cookies and internal addresses, so WireSalmon is built to keep them on your machine.

- **There is no backend.** The site is static files. Capture files are decoded by JavaScript in your browser, and live capture runs between your own computer and your own browser.
- **You can check it.** Open the developer tools, switch to the Network tab, then open a capture file. No request appears.
- **The browser enforces it.** The built site carries a Content Security Policy that forbids connections to any other host. Even if the code changed, requests carrying your data elsewhere (fetch, WebSocket, images, form posts) would be refused by the browser.

Limits worth knowing:

- The policy is part of the built site (`npm run build`, `npm run preview`). The dev server (`npm run dev`) does not carry it, because its tooling needs inline scripts.
- A policy in the page cannot stop someone from hosting a modified copy. For captures that matter, run WireSalmon from your own checkout.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Dev server with the live capture helper |
| `npm run build` | Type-check and build the static site into `dist/` |
| `npm run preview` | Serve the built site, with the live capture helper |
| `npm test` | Run the core tests |

## Project layout

```
src/core/     capture reader (pcap, pcapng), dissectors, conversation grouping, diagnosis, timing, HTTP message joining, sample generator
src/i18n/     every sentence the app shows, one file per language
src/ui/       React screens
server/       live capture helper (dumpcap → WebSocket)
test/         core tests
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit conventions and for how to add a language.

## License

[MIT](LICENSE)
