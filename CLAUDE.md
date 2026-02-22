# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project: Vigil

A lightweight network anomaly detector and intrusion detection system for embedded Linux gateways, framed as a self-hosted alternative to commercial home network monitors (Circle, Firewalla). Targets industrial IoT routers and sensor nodes.

## Architecture

The codebase is split into two distinct layers with a deliberate C/C++ boundary:

### C Layer (`src/core/`) — embedded/driver-style
- Raw packet capture via **libpcap** (`pcap_open_live`, `pcap_loop`)
- Layered header parsing: Ethernet → IP → TCP/UDP → application protocols (MQTT, HTTP, DNS)
- Connection state table using a **custom hash map** backed by a **memory pool** (no `malloc` abuse — fixed-size arena allocation)
- Exposes a clean, stable C API (public headers in `include/vigil/`) consumed by the C++ layer
- No C++ types or STL in this layer; all structs and enums are C-compatible

### C++ Layer (`src/engine/`, `src/ui/`) — intelligence and presentation
- **Protocol classifier**: state machines per protocol (MQTT, HTTP, DNS)
- **Anomaly rules engine**: traffic spike detection, unexpected protocol/destination flagging, policy config
- **ncurses dashboard** (`src/ui/dashboard/`): real-time terminal display
- **HTTP server** (`src/ui/web/`): `cpp-httplib` serving localhost:8080 with live graphs and alerts
- **Device fingerprinting**: OUI database (MAC prefix → manufacturer name) to label devices in plain English
- **Alert translator**: converts anomaly events into human-readable notifications
- **Circular log system**: fixed-size ring buffer simulating embedded flash logging constraints

### Key design constraints
- Packet capture runs in a dedicated thread; a **lock-free ring buffer** bridges the capture callback to the analysis layer (pcap callbacks are not thread-safe)
- Network byte order must be converted at parse boundaries (`ntohs`/`ntohl`)
- The C API surface in `include/vigil/` must remain stable — do not leak implementation details upward
- Memory pool sizing is determined at init time; the pool must not grow at runtime

## Build System

CMake (not yet scaffolded). Expected structure when set up:

```
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
sudo ./build/vigil --interface eth0   # raw capture requires CAP_NET_RAW (root or capability)
```

Running tests (once added):
```
cmake --build build --target tests
./build/tests/vigil_tests
```

## Key Dependencies

| Dependency | Purpose |
|---|---|
| `libpcap` | Raw packet capture |
| `ncurses` | Terminal dashboard |
| `cpp-httplib` | Embedded HTTP server (header-only) |
| `pthread` | Capture/analysis threading |

## Implementation Roadmap (current status: greenfield)

1. Raw capture + hex dump proof-of-concept
2. Ethernet → IP → TCP/UDP header parsing
3. Hash map + memory pool primitives (C)
4. Connection tracking table (C)
5. Clean C API surface (`include/vigil/`)
6. C++ consumer + basic ncurses display
7. Protocol state machines
8. Anomaly rules engine
9. HTTP server + web dashboard
10. Device fingerprinting, plain English alerts, circular logging
