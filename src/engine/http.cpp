/*
 * http.cpp — HTTP/1.1 packet classifier.
 *
 * Parses raw TCP payload bytes into an HttpEvent according to RFC 9112.
 * Extracts the start-line and selected headers (Host, User-Agent,
 * Content-Type) from the first TCP segment — no stream reassembly.
 */

#include "http.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

/* ── Helpers ──────────────────────────────────────────────────────────── */

static std::vector<std::string> split_string(const std::string &str,
                                             const std::string &delim) {
  std::vector<std::string> res{};
  size_t idx = 0;
  size_t pos;
  size_t delim_size = delim.size();

  while ((pos = str.find(delim, idx)) != std::string::npos) {
    res.push_back(str.substr(idx, pos - idx));
    idx = pos + delim_size;
  }

  res.push_back(str.substr(idx));
  return res;
}

/* Return the index of '\r' in the next CRLF pair, or npos if not found. */
static size_t find_CRLF(const char *payload, size_t pos, size_t len) {
  size_t idx = pos;

  while ((idx < len - 1) && (payload[idx] != '\r' || payload[idx + 1] != '\n'))
    idx++;

  if (idx >= len - 1)
    return std::string::npos;

  return idx;
}

/* ── Parser ───────────────────────────────────────────────────────────── */

std::optional<HttpEvent> http_parse(const uint8_t *payload,
                                    const uint16_t len) {
  if (!payload || !len)
    return std::nullopt;

  HttpEvent ev{};

  /* ── Start-line ──────────────────────────────────────────────────── */

  size_t idx = find_CRLF((char *)payload, 0, len);
  if (idx == std::string::npos)
    return std::nullopt;

  std::vector<std::string> start_line =
      split_string(std::string((char *)payload, idx), " ");

  if (start_line.size() < 3)
    return std::nullopt;

  const std::string &method = start_line[0];

  if (method == "HTTP/1.1") {
    ev.is_response = true;
    ev.status = (uint16_t)std::stoi(start_line[1]);
  } else {
    ev.is_response = false;

    struct {
      const char *name;
      HttpMethodTypes type;
    } methods[] = {
        {"GET", HttpMethodTypes::GET},
        {"HEAD", HttpMethodTypes::HEAD},
        {"POST", HttpMethodTypes::POST},
    };

    ev.method_type = HttpMethodTypes::UNKNOWN;
    for (auto &[name, type] : methods)
      if (method == name) { ev.method_type = type; break; }

    ev.URI = start_line[1];
  }

  /* ── Header fields ───────────────────────────────────────────────── */

  idx += 2; /* skip start-line CRLF */
  size_t line_end;

  while ((line_end = find_CRLF((char *)payload, idx, len)) !=
         std::string::npos) {
    if (line_end == idx) /* empty line — end of headers */
      break;

    std::vector<std::string> header = split_string(
        std::string((char *)&payload[idx], line_end - idx), ": ");

    if (header.size() < 2) {
      idx = line_end + 2;
      continue;
    }

    const std::string &key = header[0];
    const std::string &value = header[1];

    struct {
      const char *name;
      std::string HttpEvent::*field;
    } targets[] = {
        {"Host", &HttpEvent::host},
        {"User-Agent", &HttpEvent::user_agent},
        {"Content-Type", &HttpEvent::content_type},
    };

    for (auto &[name, field] : targets)
      if (key == name) { ev.*field = value; break; }

    idx = line_end + 2;
  }

  return ev;
}
