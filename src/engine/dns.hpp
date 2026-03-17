/*
 * dns.hpp — DNS packet classifier.
 *
 * Parses raw UDP payload bytes into a DnsEvent according to RFC 1035 §4.
 * Only handles standard queries/responses (opcode 0) over UDP.
 */

#pragma once

#include "protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

/* Parse a raw DNS payload into a DnsEvent.
 * Returns std::nullopt if the packet is malformed or truncated. */
std::optional<DnsEvent> dns_parse(const uint8_t *payload, uint16_t len);
