#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <map>
#include <string>

extern "C" {
#include "vigil/flowkey.h"
}

struct FlowStats {
  FlowKey key;
  uint64_t packets;
  uint64_t bytes;
  struct timespec first_seen;
  struct timespec last_seen;
};

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

inline std::string ip_to_str(uint32_t ip_net) {
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_net, buf, sizeof(buf));
  return buf;
}

inline std::string proto_to_str(uint8_t proto) {
  switch (proto) {
  case IPPROTO_TCP:
    return "TCP";
  case IPPROTO_UDP:
    return "UDP";
  default:
    return "???";
  }
}

inline std::string format_bytes(uint64_t bytes) {
  if (bytes < 1024)
    return std::to_string(bytes) + " B";
  if (bytes < 1024 * 1024)
    return std::to_string(bytes / 1024) + " KB";
  return std::to_string(bytes / (1024 * 1024)) + " MB";
}
