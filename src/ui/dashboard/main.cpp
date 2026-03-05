#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <map>
#include <pthread.h>
#include <string>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>

extern "C" {
#include "vigil/capture.h"
#include "vigil/hashmap.h"
#include "vigil/spscbuff.h"
}

/* ── Signal handling ─────────────────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;
static CaptureHandle *g_handle = nullptr;

static void signal_handler(int) {
  g_running = 0;
  if (g_handle)
    capture_stop(g_handle);
}

/* ── Capture thread ──────────────────────────────────────────────────── */

static void *capture_thread_fn(void *arg) {
  auto *handle = static_cast<CaptureHandle *>(arg);
  capture_start(handle);
  return nullptr;
}

/* ── Flow snapshot for display ───────────────────────────────────────── */

struct FlowStats {
  FlowKey key;
  uint64_t packets;
  uint64_t bytes;
  struct timespec first_seen;
  struct timespec last_seen;
};

/* FlowKey comparator for std::map */
struct FlowKeyCmp {
  bool operator()(const FlowKey &a, const FlowKey &b) const {
    if (a.src_ip != b.src_ip) return a.src_ip < b.src_ip;
    if (a.dst_ip != b.dst_ip) return a.dst_ip < b.dst_ip;
    if (a.protocol != b.protocol) return a.protocol < b.protocol;
    if (a.src_port != b.src_port) return a.src_port < b.src_port;
    return a.dst_port < b.dst_port;
  }
};

using FlowMap = std::map<FlowKey, FlowStats, FlowKeyCmp>;

/* ── Helpers ─────────────────────────────────────────────────────────── */

static std::string ip_to_str(uint32_t ip_net) {
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_net, buf, sizeof(buf));
  return buf;
}

static std::string proto_to_str(uint8_t proto) {
  switch (proto) {
  case IPPROTO_TCP: return "TCP";
  case IPPROTO_UDP: return "UDP";
  default: return "???";
  }
}

static std::string format_bytes(uint64_t bytes) {
  if (bytes < 1024) return std::to_string(bytes) + " B";
  if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + " KB";
  return std::to_string(bytes / (1024 * 1024)) + " MB";
}

/* ── Main ────────────────────────────────────────────────────────────── */

static constexpr size_t RINGBUF_CAPACITY = 4096;

int main(int argc, char *argv[]) {
  /* Parse CLI args */
  char *interface_name = nullptr;
  char devbuf[256];

  for (int i = 1; i < argc; i++) {
    interface_name = argv[i];
  }

  if (!interface_name) {
    char errbuf[VIGIL_ERRBUF_SIZE];
    if (capture_default_device(devbuf, sizeof(devbuf), errbuf) == -1) {
      fprintf(stderr, "No interfaces found: %s\n", errbuf);
      return 1;
    }
    interface_name = devbuf;
  }

  /* Init ring buffer */
  RingBuf *rb = ringbuf_init(RINGBUF_CAPACITY);
  if (!rb) {
    fprintf(stderr, "Failed to allocate ring buffer\n");
    return 1;
  }

  /* Init capture */
  CaptureConfig config{};
  config.interface_name = interface_name;
  config.snapshot_length = 262144;
  config.promiscuous = 1;
  config.capture_timeout = 1000;
  config.verbose = 0;

  CaptureHandle *handle = capture_open(&config);
  if (!handle) {
    fprintf(stderr, "capture_open failed: %s\n", config.errbuf);
    ringbuf_free(rb);
    return 1;
  }
  capture_attach_ringbuf(handle, rb);
  g_handle = handle;

  /* Install signal handlers */
  struct sigaction sa{};
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);

  /* Spawn capture thread */
  pthread_t cap_thread;
  if (pthread_create(&cap_thread, nullptr, capture_thread_fn, handle) != 0) {
    fprintf(stderr, "Failed to create capture thread\n");
    capture_close(handle);
    ringbuf_free(rb);
    return 1;
  }

  /* ── FTXUI dashboard ─────────────────────────────────────────────── */

  FlowMap flows;
  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t dropped_events = 0;

  auto screen = ftxui::ScreenInteractive::Fullscreen();

  /* Theme colors matching sway config */
  auto const lavender   = ftxui::Color::RGB(191, 158, 240);  /* #bf9ef0 — accent */
  auto const cream      = ftxui::Color::RGB(216, 202, 184);  /* #d8cab8 — text */
  auto const dark_bg    = ftxui::Color::RGB(20, 18, 22);     /* #141216 — background */
  auto const dark_purp  = ftxui::Color::RGB(43, 33, 53);     /* #2b2135 — secondary */
  auto const urgent_red = ftxui::Color::RGB(252, 70, 73);    /* #fc4649 — urgent */
  auto const muted      = ftxui::Color::RGB(120, 100, 140);  /* muted lavender for dim text */
  auto const tcp_color  = ftxui::Color::RGB(160, 220, 180);  /* soft green for TCP */
  auto const udp_color  = ftxui::Color::RGB(140, 180, 240);  /* soft blue for UDP */

  auto renderer = ftxui::Renderer([&] {
    using namespace ftxui;

    /* Drain ring buffer */
    PacketEvent ev;
    while (ringbuf_pop(rb, &ev)) {
      total_packets++;
      total_bytes += ev.packet_len;

      auto it = flows.find(ev.key);
      if (it != flows.end()) {
        it->second.packets++;
        it->second.bytes += ev.packet_len;
        it->second.last_seen = ev.timestamp;
      } else {
        FlowStats stats{};
        stats.key = ev.key;
        stats.packets = 1;
        stats.bytes = ev.packet_len;
        stats.first_seen = ev.timestamp;
        stats.last_seen = ev.timestamp;
        flows[ev.key] = stats;
      }
    }

    /* Build flow table rows */
    std::vector<std::vector<std::string>> rows;
    rows.push_back({"Proto", "Source", "Destination", "Packets", "Bytes"});

    for (auto &[key, stats] : flows) {
      rows.push_back({
          proto_to_str(key.protocol),
          ip_to_str(key.src_ip) + ":" + std::to_string(ntohs(key.src_port)),
          ip_to_str(key.dst_ip) + ":" + std::to_string(ntohs(key.dst_port)),
          std::to_string(stats.packets),
          format_bytes(stats.bytes),
      });
    }

    auto table = Table(rows);
    table.SelectAll().Border(LIGHT);
    table.SelectAll().Decorate(color(cream));

    /* Header row — lavender accent */
    table.SelectRow(0).Decorate(bold);
    table.SelectRow(0).DecorateCells(color(lavender));
    table.SelectRow(0).SeparatorVertical(LIGHT);
    table.SelectRow(0).Border(DOUBLE);

    /* Alternate row shading */
    for (int i = 2; i < (int)rows.size(); i += 2) {
      table.SelectRow(i).DecorateCells(color(muted));
    }

    /* Right-align numeric columns */
    table.SelectColumn(3).DecorateCells(align_right);
    table.SelectColumn(4).DecorateCells(align_right);

    /* Protocol column color coding */
    for (int i = 1; i < (int)rows.size(); i++) {
      if (rows[i][0] == "TCP") {
        table.SelectCell(0, i).DecorateCells(color(tcp_color));
      } else if (rows[i][0] == "UDP") {
        table.SelectCell(0, i).DecorateCells(color(udp_color));
      }
    }

    /* Title bar */
    auto title = hbox({
        text(" VIGIL ") | bold | color(dark_bg) | bgcolor(lavender),
        text("  Network Monitor") | bold | color(lavender),
    });

    /* Status bar */
    auto status = hbox({
        text(" " + std::string(interface_name) + " ") | bold | bgcolor(dark_purp) | color(cream),
        text("  "),
        text("Flows ") | color(muted),
        text(std::to_string(flows.size())) | bold | color(cream),
        text("    Packets ") | color(muted),
        text(std::to_string(total_packets)) | bold | color(cream),
        text("    Traffic ") | color(muted),
        text(format_bytes(total_bytes)) | bold | color(lavender),
        filler(),
        text(" Ctrl+C to quit ") | color(muted),
    });

    /* Empty state */
    Element content;
    if (flows.empty()) {
      content = vbox({
          filler(),
          text("Waiting for packets...") | center | color(muted),
          filler(),
      }) | flex;
    } else {
      content = table.Render() | flex | vscroll_indicator | frame;
    }

    return vbox({
        title,
        separator() | color(dark_purp),
        status,
        separator() | color(dark_purp),
        content,
    }) | border | borderStyled(ROUNDED, lavender);
  });

  /* Refresh loop — use a separate thread to post custom events at ~2Hz */
  pthread_t refresh_thread;
  pthread_create(
      &refresh_thread, nullptr,
      [](void *arg) -> void * {
        auto *scr = static_cast<ftxui::ScreenInteractive *>(arg);
        while (g_running) {
          struct timespec ts = {0, 500000000}; /* 500ms */
          nanosleep(&ts, nullptr);
          scr->Post(ftxui::Event::Custom);
        }
        scr->ExitLoopClosure()();
        return nullptr;
      },
      &screen);

  screen.Loop(renderer);

  /* ── Shutdown ────────────────────────────────────────────────────── */

  g_running = 0;
  capture_stop(handle);
  pthread_join(cap_thread, nullptr);
  pthread_join(refresh_thread, nullptr);
  capture_close(handle);
  ringbuf_free(rb);

  return 0;
}
