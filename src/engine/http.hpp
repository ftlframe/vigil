#pragma once

#include "protocol.hpp"
#include <cstdint>
#include <optional>

/* Parse a raw HTTP payload into a HttpEvent
 * Returns a std::nullopt if the packet is malformed or truncated */
std::optional<HttpEvent> http_parse(const uint8_t *payload, const uint16_t len);
