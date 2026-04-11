#pragma once

#include <algorithm>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

const std::unordered_set<std::string> known_suffixes = {
    "co.uk",  "org.uk", "ac.uk",  "gov.uk", "com.au", "org.au", "net.au",
    "co.jp",  "or.jp",  "ne.jp",  "co.nz",  "co.kr",  "co.in",  "com.br",
    "org.br", "com.mx", "com.cn", "com.tw", "co.za",  "co.il"};

inline std::string base_domain(const std::string &qname) {
  auto d1 = qname.rfind('.');
  if (d1 == std::string::npos)
    return qname;

  auto d2 = qname.rfind('.', d1 - 1);
  if (d2 == std::string::npos)
    return qname;

  std::string tail = qname.substr(d2 + 1);

  if (known_suffixes.count(tail)) {
    auto d3 = qname.rfind('.', d2 - 1);
    if (d3 == std::string::npos)
      return qname;
    return qname.substr(d3 + 1);
  }

  return tail;
}

struct DomainGroup {
  unsigned query_count = 0;
  unsigned response_count = 0;
  std::vector<std::string> resolved_ips;
};
