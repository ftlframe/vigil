#pragma once
#include <stdint.h>

/* 5-tuple that uniquely identifies a connection */
typedef struct FlowKey {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t protocol;
  uint16_t src_port;
  uint16_t dst_port;
} FlowKey;
