#pragma once

#include <deque>
#include <map>
#include <string>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>

#include "dns_helpers.hpp"
#include "flow_types.hpp"
#include "theme.hpp"

#include "engine/dns.hpp"
#include "engine/http.hpp"

/* ── Title bar ───────────────────────────────────────────────────────── */

inline ftxui::Element render_title(ftxui::Component &filter_input) {
  using namespace ftxui;
  using namespace theme;

  return hbox({
      text(" VIGIL ") | bold | color(dark_bg) | bgcolor(lavender),
      text("  Network Monitor") | bold | color(lavender),
      filler(),
      text(" Filter: ") | color(muted),
      filter_input->Render() | size(WIDTH, EQUAL, 24) | color(cream),
      text(" "),
  });
}

/* ── Flow table ──────────────────────────────────────────────────────── */

inline ftxui::Element render_flow_table(
    const std::vector<std::vector<std::string>> &rows, const FlowMap &flows,
    int total_data_rows, int scroll_offset) {
  using namespace ftxui;
  using namespace theme;

  if (rows.size() <= 1) {
    auto msg =
        flows.empty() ? "Waiting for packets..." : "No flows match filter";
    return vbox({
               filler(),
               text(msg) | center | color(muted),
               filler(),
           }) |
           flex;
  }

  auto table = Table(rows);
  table.SelectAll().SeparatorVertical(LIGHT);

  /* Header row — centered, accented, with a clean bottom border */
  table.SelectRow(0).Decorate(bold);
  table.SelectRow(0).DecorateCells(color(lavender));
  table.SelectRow(0).DecorateCells(center);
  table.SelectRow(0).Border(LIGHT);

  /* Alternate row striping — subtle background contrast */
  for (int i = 1; i < (int)rows.size(); i++) {
    if (i % 2 == 0)
      table.SelectRow(i).DecorateCells(bgcolor(row_stripe));
  }

  /* Stretch IP columns to fill available width */
  table.SelectColumn(1).DecorateCells(flex);
  table.SelectColumn(3).DecorateCells(flex);

  /* Center protocol and port columns */
  table.SelectColumn(0).DecorateCells(center);
  table.SelectColumn(2).DecorateCells(center);
  table.SelectColumn(4).DecorateCells(center);

  /* Right-align numeric columns, cream text */
  table.SelectColumn(5).DecorateCells(align_right);
  table.SelectColumn(5).DecorateCells(color(cream));
  table.SelectColumn(6).DecorateCells(align_right);
  table.SelectColumn(6).DecorateCells(color(cream));

  /* Column-specific colors */
  for (int i = 1; i < (int)rows.size(); i++) {
    /* Protocol — color by type */
    if (rows[i][0] == "TCP") {
      table.SelectCell(0, i).DecorateCells(color(tcp_color));
    } else if (rows[i][0] == "UDP") {
      table.SelectCell(0, i).DecorateCells(color(udp_color));
    }
    /* Source — warm IP, bright port */
    table.SelectCell(1, i).DecorateCells(color(src_color));
    table.SelectCell(2, i).DecorateCells(color(src_port_color) | bold);
    /* Destination — cool IP, bright port */
    table.SelectCell(3, i).DecorateCells(color(dst_color));
    table.SelectCell(4, i).DecorateCells(color(dst_port_color) | bold);
  }

  float scroll_y = total_data_rows > 1
                       ? (float)scroll_offset / (float)(total_data_rows - 1)
                       : 0.0f;
  return table.Render() | focusPositionRelative(0.0f, scroll_y) |
         vscroll_indicator | yframe | flex;
}

/* ── Sidebar (stats + DNS log) ───────────────────────────────────────── */

inline ftxui::Element render_sidebar(const char *interface_name,
                                     size_t visible_flows, size_t total_flows,
                                     uint64_t total_packets,
                                     uint64_t total_bytes, bool filtered,
                                     const std::deque<DnsEvent> &dns_log,
                                     const std::deque<HttpEvent> &http_log) {
  using namespace ftxui;
  using namespace theme;

  /* DNS log entries */
  Elements dns_entries;
  for (auto it = dns_log.rbegin();
       it != dns_log.rend() && dns_entries.size() < 8; ++it) {
    std::string prefix = it->is_response ? "< " : "> ";
    std::string line = prefix + it->qname;
    if (it->is_response && !it->answers.empty())
      line += " -> " + it->answers[0].data;
    if (it->is_response && it->rcode == 3)
      line = prefix + it->qname + " NXDOMAIN";
    dns_entries.push_back(text(" " + line) | color(cream));
  }
  if (dns_entries.empty())
    dns_entries.push_back(text(" No DNS yet") | color(muted));

  /* HTTP log entries */
  Elements http_entries;
  for (auto it = http_log.rbegin();
       it != http_log.rend() && http_entries.size() < 8; ++it) {
    std::string line;
    if (it->is_response) {
      line = "< " + std::to_string(it->status) + " " + it->content_type;
    } else {
      std::string method;
      switch (it->method_type) {
      case HttpMethodTypes::GET:  method = "GET";  break;
      case HttpMethodTypes::HEAD: method = "HEAD"; break;
      case HttpMethodTypes::POST: method = "POST"; break;
      default:                    method = "???";  break;
      }
      line = "> " + method + " " + it->host + it->URI;
    }
    http_entries.push_back(text(" " + line) | color(cream));
  }
  if (http_entries.empty())
    http_entries.push_back(text(" No HTTP yet") | color(muted));

  return vbox({
             text(" Stats") | bold | color(lavender),
             separator() | color(dark_purp),
             text(""),
             hbox({text(" Interface ") | color(muted)}),
             hbox({text("  " + std::string(interface_name)) | bold |
                   color(cream)}),
             text(""),
             hbox({text(" Flows ") | color(muted)}),
             hbox({text("  " + std::to_string(visible_flows) +
                        (filtered ? "/" + std::to_string(total_flows) : "")) |
                   bold | color(cream)}),
             text(""),
             hbox({text(" Packets ") | color(muted)}),
             hbox({text("  " + std::to_string(total_packets)) | bold |
                   color(cream)}),
             text(""),
             hbox({text(" Traffic ") | color(muted)}),
             hbox({text("  " + format_bytes(total_bytes)) | bold |
                   color(lavender)}),
             text(""),
             separator() | color(dark_purp),
             text(" DNS Log") | bold | color(lavender),
             separator() | color(dark_purp),
             vbox(dns_entries),
             text(""),
             separator() | color(dark_purp),
             text(" HTTP Log") | bold | color(lavender),
             separator() | color(dark_purp),
             vbox(http_entries),
             filler(),
             text(" Ctrl+C to quit") | color(muted),
             text(""),
         }) |
         size(WIDTH, EQUAL, 36) | borderStyled(ROUNDED, dark_purp);
}

/* ── HTTP popup ──────────────────────────────────────────────────────── */

inline ftxui::Element render_http_popup(const std::deque<HttpEvent> &http_log) {
  using namespace ftxui;
  using namespace theme;

  Elements rows;
  for (auto it = http_log.rbegin(); it != http_log.rend(); ++it) {
    if (it->is_response) {
      rows.push_back(hbox({
          text(" < ") | color(muted),
          text(std::to_string(it->status)) | bold |
              color(it->status >= 400 ? ftxui::Color::Red
                                      : ftxui::Color::Green),
          text(" " + it->content_type) | color(cream),
      }));
    } else {
      std::string method;
      switch (it->method_type) {
      case HttpMethodTypes::GET:  method = "GET";  break;
      case HttpMethodTypes::HEAD: method = "HEAD"; break;
      case HttpMethodTypes::POST: method = "POST"; break;
      default:                    method = "???";  break;
      }
      rows.push_back(hbox({
          text(" > ") | color(muted),
          text(method + " ") | bold | color(lavender),
          text(it->host + it->URI) | color(cream),
      }));
      if (!it->user_agent.empty())
        rows.push_back(text("   UA: " + it->user_agent) | color(muted));
    }
    rows.push_back(separator() | color(dark_purp));
  }
  if (rows.empty())
    rows.push_back(text(" No HTTP data yet") | color(muted));

  return vbox({
             text(" HTTP Requests (Esc to close)") | bold | color(lavender),
             separator() | color(dark_purp),
             vbox(rows) | vscroll_indicator | yframe | flex,
         }) |
         size(WIDTH, EQUAL, 70) | size(HEIGHT, LESS_THAN, 30) |
         borderStyled(ROUNDED, lavender) | clear_under | center;
}

/* ── DNS popup ───────────────────────────────────────────────────────── */

inline ftxui::Element render_dns_popup(const std::deque<DnsEvent> &dns_log) {
  using namespace ftxui;
  using namespace theme;

  /* Build grouped data */
  std::map<std::string, DomainGroup> groups;
  for (auto &ev : dns_log) {
    auto &g = groups[base_domain(ev.qname)];
    if (ev.is_response) {
      g.response_count++;
      for (auto &ans : ev.answers) {
        if (std::find(g.resolved_ips.begin(), g.resolved_ips.end(), ans.data) ==
            g.resolved_ips.end())
          g.resolved_ips.push_back(ans.data);
      }
    } else {
      g.query_count++;
    }
  }

  Elements domain_rows;
  for (auto &[domain, g] : groups) {
    domain_rows.push_back(hbox({
        text(" " + domain) | bold | color(cream) | flex,
        text(std::to_string(g.query_count) + "q/" +
             std::to_string(g.response_count) + "r ") |
            color(muted),
    }));
    for (auto &ip : g.resolved_ips) {
      domain_rows.push_back(text("   -> " + ip) | color(muted));
    }
    domain_rows.push_back(separator() | color(dark_purp));
  }
  if (domain_rows.empty())
    domain_rows.push_back(text(" No DNS data yet") | color(muted));

  return vbox({
             text(" DNS Domains (Esc to close)") | bold | color(lavender),
             separator() | color(dark_purp),
             vbox(domain_rows) | vscroll_indicator | yframe | flex,
         }) |
         size(WIDTH, EQUAL, 60) | size(HEIGHT, LESS_THAN, 30) |
         borderStyled(ROUNDED, lavender) | clear_under | center;
}
