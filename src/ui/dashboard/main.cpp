#include <algorithm>
#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <map>
#include <pthread.h>
#include <string>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
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
    if (a.src_ip != b.src_ip)
      return a.src_ip < b.src_ip;
    if (a.dst_ip != b.dst_ip)
      return a.dst_ip < b.dst_ip;
    if (a.protocol != b.protocol)
      return a.protocol < b.protocol;
    if (a.src_port != b.src_port)
      return a.src_port < b.src_port;
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
  case IPPROTO_TCP:
    return "TCP";
  case IPPROTO_UDP:
    return "UDP";
  default:
    return "???";
  }
}

static std::string format_bytes(uint64_t bytes) {
  if (bytes < 1024)
    return std::to_string(bytes) + " B";
  if (bytes < 1024 * 1024)
    return std::to_string(bytes / 1024) + " KB";
  return std::to_string(bytes / (1024 * 1024)) + " MB";
}

/* ── Main ────────────────────────────────────────────────────────────── */

static constexpr size_t RINGBUF_CAPACITY = 4096;

int main(int argc, char *argv[]) {
  /* Parse CLI args — only accepted argument is the interface name */
  char *interface_name = nullptr;
  char devbuf[256];

  if (argc > 2) {
    fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
    return 1;
  }
  if (argc == 2)
    interface_name = argv[1];

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

  auto screen = ftxui::ScreenInteractive::Fullscreen();

  /* Theme colors matching sway config */
  auto const lavender = ftxui::Color::RGB(191, 158, 240); /* #bf9ef0 — accent */
  auto const cream = ftxui::Color::RGB(216, 202, 184);    /* #d8cab8 — text */
  auto const dark_bg = ftxui::Color::RGB(20, 18, 22); /* #141216 — background */
  auto const dark_purp =
      ftxui::Color::RGB(43, 33, 53); /* #2b2135 — secondary */
  auto const muted =
      ftxui::Color::RGB(120, 100, 140); /* muted lavender for dim text */
  auto const tcp_color =
      ftxui::Color::RGB(160, 220, 180); /* soft green for TCP */
  auto const udp_color =
      ftxui::Color::RGB(140, 180, 240); /* soft blue for UDP */

  /* Filter input */
  std::string filter_text;
  auto filter_input = ftxui::Input(&filter_text, "IP or port...");
  int scroll_offset = 0;
  int total_data_rows = 0;
  time_t last_eviction = 0;

  auto renderer = ftxui::Renderer(filter_input, [&] {
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

    /* Evict flows idle longer than 60s */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - last_eviction > 10) {
      last_eviction = now.tv_sec;
      for (auto it = flows.begin(); it != flows.end();) {
        if (now.tv_sec - it->second.last_seen.tv_sec > 60)
          it = flows.erase(it);
        else
          ++it;
      }
    }

    /* Build flow table rows — apply filter */
    std::vector<std::vector<std::string>> rows;
    rows.push_back({"Proto", "Source", "Destination", "Packets", "Bytes"});

    for (auto &[key, stats] : flows) {
      auto src =
          ip_to_str(key.src_ip) + ":" + std::to_string(ntohs(key.src_port));
      auto dst =
          ip_to_str(key.dst_ip) + ":" + std::to_string(ntohs(key.dst_port));
      auto proto = proto_to_str(key.protocol);

      if (!filter_text.empty()) {
        if (src.find(filter_text) == std::string::npos &&
            dst.find(filter_text) == std::string::npos &&
            proto.find(filter_text) == std::string::npos)
          continue;
      }

      rows.push_back({
          proto,
          src,
          dst,
          std::to_string(stats.packets),
          format_bytes(stats.bytes),
      });
    }

    total_data_rows = (int)rows.size() - 1;
    scroll_offset =
        std::max(0, std::min(scroll_offset, std::max(0, total_data_rows - 1)));

    auto table = Table(rows);
    table.SelectAll().Border(LIGHT);
    table.SelectAll().DecorateCells(color(cream));

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

    size_t visible_flows = rows.size() - 1;

    /* Title bar */
    auto title = hbox({
        text(" VIGIL ") | bold | color(dark_bg) | bgcolor(lavender),
        text("  Network Monitor") | bold | color(lavender),
        filler(),
        text(" Filter: ") | color(muted),
        filter_input->Render() | size(WIDTH, EQUAL, 24) | color(cream),
        text(" "),
    });

    /* Table content */
    Element table_content;
    if (rows.size() <= 1) {
      auto msg =
          flows.empty() ? "Waiting for packets..." : "No flows match filter";
      table_content = vbox({
                          filler(),
                          text(msg) | center | color(muted),
                          filler(),
                      }) |
                      flex;
    } else {
      float scroll_y = total_data_rows > 1
                           ? (float)scroll_offset / (float)(total_data_rows - 1)
                           : 0.0f;
      table_content = table.Render() | focusPositionRelative(0.0f, scroll_y) |
                      vscroll_indicator | yframe | flex;
    }

    /* Right sidebar — stats panel */
    auto sidebar = vbox({
                       text(" Stats") | bold | color(lavender),
                       separator() | color(dark_purp),
                       text(""),
                       hbox({text(" Interface ") | color(muted)}),
                       hbox({text("  " + std::string(interface_name)) | bold |
                             color(cream)}),
                       text(""),
                       hbox({text(" Flows ") | color(muted)}),
                       hbox({text("  " + std::to_string(visible_flows) +
                                  (filter_text.empty()
                                       ? ""
                                       : "/" + std::to_string(flows.size()))) |
                             bold | color(cream)}),
                       text(""),
                       hbox({text(" Packets ") | color(muted)}),
                       hbox({text("  " + std::to_string(total_packets)) | bold |
                             color(cream)}),
                       text(""),
                       hbox({text(" Traffic ") | color(muted)}),
                       hbox({text("  " + format_bytes(total_bytes)) | bold |
                             color(lavender)}),
                       filler(),
                       text(" Ctrl+C to quit") | color(muted),
                       text(""),
                   }) |
                   size(WIDTH, EQUAL, 20) | borderStyled(ROUNDED, dark_purp);

    /* Main content — table + sidebar */
    auto content = hbox({
        table_content,
        sidebar,
    });

    return vbox({
               title,
               separator() | color(dark_purp),
               content | flex,
           }) |
           border | borderStyled(ROUNDED, lavender);
  });

  /* Scroll events — mouse wheel + PageUp/PageDown always scroll the table,
   * all other keys go to the filter input */
  auto component = ftxui::CatchEvent(renderer, [&](ftxui::Event event) {
    if (event.is_mouse()) {
      if (event.mouse().button == ftxui::Mouse::WheelUp) {
        scroll_offset = std::max(0, scroll_offset - 3);
        return true;
      }
      if (event.mouse().button == ftxui::Mouse::WheelDown) {
        scroll_offset =
            std::min(std::max(0, total_data_rows - 1), scroll_offset + 3);
        return true;
      }
    }
    if (event == ftxui::Event::PageUp) {
      scroll_offset = std::max(0, scroll_offset - 20);
      return true;
    }
    if (event == ftxui::Event::PageDown) {
      scroll_offset =
          std::min(std::max(0, total_data_rows - 1), scroll_offset + 20);
      return true;
    }
    return false;
  });

  /* Refresh loop — use a separate thread to post custom events at ~2Hz */
  pthread_t refresh_thread;
  if (pthread_create(
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
          &screen) != 0) {
    fprintf(stderr, "Failed to create refresh thread\n");
    capture_stop(handle);
    g_running = 0;
    pthread_join(cap_thread, nullptr);
    capture_close(handle);
    ringbuf_free(rb);
    return 1;
  }

  screen.Loop(component);

  /* ── Shutdown ────────────────────────────────────────────────────── */

  g_running = 0;
  pthread_join(cap_thread, nullptr);
  pthread_join(refresh_thread, nullptr);
  capture_close(handle);
  ringbuf_free(rb);

  return 0;
}
