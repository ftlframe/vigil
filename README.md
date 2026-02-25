# Vigil

A lightweight network anomaly detector and intrusion detection system for embedded Linux gateways. Self-hosted alternative to commercial home network monitors (Circle, Firewalla).

## Architecture

Two-layer design with a clean C/C++ boundary:

- **C Core** (`src/core/`) — raw packet capture (libpcap), header parsing, hash map, memory pool, connection tracking
- **C++ Engine** (`src/engine/`) — protocol classification, anomaly detection, alerting
- **UI** (`src/ui/`) — ncurses terminal dashboard + embedded HTTP server (localhost:8080)

## Building

```bash
cmake -B build
cmake --build build
sudo ./build/vigil
```

Requires `libpcap-devel` and root/CAP_NET_RAW for raw capture.

## Roadmap

- [x] Raw packet capture + hex dump
- [x] Ethernet / IPv4 / TCP / UDP header parsing
- [x] Hash map + memory pool primitives (C)
- [x] Connection tracking table (5-tuple keyed)
- [ ] Stable C API surface (`include/vigil/`)
- [ ] C++ consumer + ncurses dashboard
- [ ] Protocol state machines (MQTT, HTTP, DNS)
- [ ] Anomaly rules engine
- [ ] HTTP server + web dashboard
- [ ] Device fingerprinting, plain-English alerts, circular logging

## Dependencies

| Dependency | Purpose |
|---|---|
| libpcap | Raw packet capture |
| ncurses | Terminal dashboard |
| cpp-httplib | Embedded HTTP server (header-only) |
| pthread | Capture/analysis threading |
