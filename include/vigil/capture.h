#pragma once
#include <stdint.h>
#include <pcap.h>

typedef struct {
  char* interface_name;
  uint32_t snapshot_length;
  uint32_t promiscuous;
  uint32_t capture_timeout;
  int verbose;
  char errbuf[PCAP_ERRBUF_SIZE];
} CaptureConfig;

/* Forward declarations */
typedef struct Arena Arena;
typedef struct FlowTable FlowTable;

typedef struct {
  Arena* arena;
  FlowTable* flow_table;
  pcap_t* pcap;
  int verbose;  /* copied from config at open time */
} CaptureHandle;


CaptureHandle* capture_open(CaptureConfig* config);
void capture_stop(CaptureHandle* handle);

int capture_start(CaptureHandle* handle);
void capture_close(CaptureHandle* handle);
