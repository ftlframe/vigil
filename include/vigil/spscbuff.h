#pragma once

#include "vigil/hashmap.h"
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
#include <atomic>
#define VIGIL_ATOMIC(T) std::atomic<T>
#define VIGIL_ALIGNAS(N) alignas(N)
#else
#include <stdatomic.h>
#include <stdbool.h>
#define VIGIL_ATOMIC(T) _Atomic T
#define VIGIL_ALIGNAS(N) _Alignas(N)
#endif

#if defined(__aarch64__) && defined(__APPLE__)
#define CACHE_LINE_SIZE 128
#else
#define CACHE_LINE_SIZE 64
#endif

/* Per-packet data passed from capture thread to UI thread.
 * The UI thread aggregates these into its own flow table. */
typedef struct PacketEvent {
  FlowKey key;
  uint32_t packet_len;
  struct timespec timestamp;
} PacketEvent;

/* Lock-free single-producer single-consumer ring buffer (Vyukov/rigtorp
 * pattern).
 *
 * One slack slot is always kept empty so that write==read means empty
 * and (write+1)%cap==read means full — no ambiguity, no separate count.
 *
 * Fields are grouped by ownership and cache-line aligned to prevent
 * false sharing between producer and consumer cores:
 *   - write + read_cache  → producer's cache line
 *   - read  + write_cache → consumer's cache line
 *
 * The *_cache fields are lazy local copies of the other thread's index.
 * They avoid expensive atomic loads on every operation — only refreshed
 * when the fast path (cache check) suggests the buffer is full/empty. */
typedef struct RingBuf {
  size_t capacity;    /* slot count including slack (user capacity + 1) */
  PacketEvent *slots; /* contiguous array, allocated after struct */

  VIGIL_ALIGNAS(CACHE_LINE_SIZE)
  VIGIL_ATOMIC(size_t)
  write;             /* next slot producer will write (producer-owned) */
  size_t read_cache; /* producer's stale copy of read index */

  VIGIL_ALIGNAS(CACHE_LINE_SIZE)
  VIGIL_ATOMIC(size_t) read; /* next slot consumer will read (consumer-owned) */
  size_t write_cache;        /* consumer's stale copy of write index */
} RingBuf;

RingBuf *ringbuf_init(size_t capacity);
void ringbuf_free(RingBuf *rb);

/* Non-blocking push. Returns false if buffer is full (event dropped). */
bool ringbuf_push(RingBuf *rb, PacketEvent in);

/* Non-blocking pop. Returns false if buffer is empty. Copies event into *out.
 */
bool ringbuf_pop(RingBuf *rb, PacketEvent *out);
