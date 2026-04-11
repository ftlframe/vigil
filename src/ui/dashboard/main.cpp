#include <csignal>
#include <cstdio>
#include <cstring>
#include <deque>
#include <pthread.h>
#include <string>

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "components.hpp"
#include "flow_types.hpp"

#include "engine/dns.hpp"

extern "C" {
#include "vigil/capture.h"
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

  using namespace theme;

  FlowMap flows;
  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;

  /* Recent DNS events — capped ring for display */
  static constexpr size_t DNS_LOG_MAX = 64;
  std::deque<DnsEvent> dns_log;

  bool show_dns_popup = false;

  auto screen = ftxui::ScreenInteractive::Fullscreen();

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

      /* Classify DNS packets (port 53 UDP) */
      if (ev.key.protocol == IPPROTO_UDP &&
          (ntohs(ev.key.src_port) == 53 || ntohs(ev.key.dst_port) == 53) &&
          ev.payload_len > 0) {
        auto dns = dns_parse(ev.payload, ev.payload_len);
        if (dns) {
          dns_log.push_back(std::move(*dns));
          if (dns_log.size() > DNS_LOG_MAX)
            dns_log.pop_front();
        }
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
    rows.push_back(
        {"Proto", "Src IP", "Port", "Dst IP", "Port", "Packets", "Bytes"});

    for (auto &[key, stats] : flows) {
      auto src_ip = ip_to_str(key.src_ip);
      auto src_port = std::to_string(ntohs(key.src_port));
      auto dst_ip = ip_to_str(key.dst_ip);
      auto dst_port = std::to_string(ntohs(key.dst_port));
      auto proto = proto_to_str(key.protocol);

      if (!filter_text.empty()) {
        if (src_ip.find(filter_text) == std::string::npos &&
            src_port.find(filter_text) == std::string::npos &&
            dst_ip.find(filter_text) == std::string::npos &&
            dst_port.find(filter_text) == std::string::npos &&
            proto.find(filter_text) == std::string::npos)
          continue;
      }

      rows.push_back({
          proto,
          src_ip,
          src_port,
          dst_ip,
          dst_port,
          std::to_string(stats.packets),
          format_bytes(stats.bytes),
      });
    }

    total_data_rows = (int)rows.size() - 1;
    scroll_offset =
        std::max(0, std::min(scroll_offset, std::max(0, total_data_rows - 1)));

    size_t visible_flows = rows.size() - 1;

    auto title = render_title(filter_input);
    auto table_content =
        render_flow_table(rows, flows, total_data_rows, scroll_offset);
    auto sidebar =
        render_sidebar(interface_name, visible_flows, flows.size(),
                       total_packets, total_bytes, !filter_text.empty(), dns_log);

    auto content = hbox({table_content, sidebar});
    auto main_layout = vbox({
                           title,
                           separator() | color(theme::dark_purp),
                           content | flex,
                       }) |
                       border | borderStyled(ROUNDED, theme::lavender);

    return dbox({main_layout, show_dns_popup ? render_dns_popup(dns_log)
                                             : emptyElement()});
  });

  /* Scroll events — mouse wheel + PageUp/PageDown always scroll the table,
   * all other keys go to the filter input */
  auto component = ftxui::CatchEvent(renderer, [&](ftxui::Event event) {
    if (event == ftxui::Event::Character('d') && !show_dns_popup) {
      show_dns_popup = true;
      return true;
    }
    if (show_dns_popup) {
      if (event == ftxui::Event::Escape) {
        show_dns_popup = false;
        return true;
      }
      return true;
    }
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
              struct timespec ts = {0, 100000000}; /* 500ms */
              nanosleep(&ts, nullptr);
              if (!g_running)
                break;
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
  capture_stop(handle);
  pthread_join(cap_thread, nullptr);
  pthread_join(refresh_thread, nullptr);
  capture_close(handle);
  ringbuf_free(rb);

  return 0;
}
