#pragma once
#include <stddef.h>
#include <stdint.h>

#define VIGIL_ERRBUF_SIZE 256

typedef struct {
  char* interface_name;
  uint32_t snapshot_length;
  uint32_t promiscuous;
  uint32_t capture_timeout;
  int verbose;
  char errbuf[VIGIL_ERRBUF_SIZE];
} CaptureConfig;

/* Opaque handle — struct defined in capture.c */
typedef struct CaptureHandle CaptureHandle;

int capture_default_device(char* name, size_t len, char* errbuf);
CaptureHandle* capture_open(CaptureConfig* config);
int capture_start(CaptureHandle* handle);
void capture_stop(CaptureHandle* handle);
void capture_close(CaptureHandle* handle);
