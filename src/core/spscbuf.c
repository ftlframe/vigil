#include "vigil/spscbuff.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

/* Single contiguous allocation: [RingBuf struct | slots array].
 * Stores capacity+1 to account for the slack element. */
RingBuf *ringbuf_init(size_t capacity) {
  size_t raw_size = sizeof(RingBuf) + sizeof(PacketEvent) * (capacity + 1);
  size_t aligned_size =
      (raw_size + (CACHE_LINE_SIZE - 1)) & ~(CACHE_LINE_SIZE - 1);
  RingBuf *rb = aligned_alloc(CACHE_LINE_SIZE, aligned_size);
  if (!rb)
    return NULL;
  rb->capacity = capacity + 1;
  rb->slots = (PacketEvent *)((char *)rb + sizeof(RingBuf));
  memset(rb->slots, 0, sizeof(PacketEvent) * (capacity + 1));
  rb->read = 0;
  rb->write = 0;
  rb->read_cache = 0;
  rb->write_cache = 0;
  return rb;
}

void ringbuf_free(RingBuf *ringbuf) { free(ringbuf); }

/* Producer side (capture thread).
 * 1. Read own write index (relaxed — sole writer)
 * 2. Wrap next index at capacity boundary
 * 3. Fast path: check cached read index (no atomic, no cross-core traffic)
 *    Slow path: refresh cache with acquire load of consumer's read index
 *    If still full: drop the event (return false)
 * 4. Write slot, then publish new write index with release store
 *    (release guarantees slot data is visible before the index update) */
bool ringbuf_push(RingBuf *rb, PacketEvent in) {
  size_t writeIdx = atomic_load_explicit(&rb->write, memory_order_relaxed);
  size_t nextWriteIdx = writeIdx + 1;

  if (nextWriteIdx == rb->capacity)
    nextWriteIdx = 0;

  if (nextWriteIdx == rb->read_cache) {
    rb->read_cache = atomic_load_explicit(&rb->read, memory_order_acquire);
    if (nextWriteIdx == rb->read_cache)
      return false;
  }

  rb->slots[writeIdx] = in;
  atomic_store_explicit(&rb->write, nextWriteIdx, memory_order_release);
  return true;
}

/* Consumer side (UI thread).
 * 1. Read own read index (relaxed — sole writer)
 * 2. Wrap next index at capacity boundary
 * 3. Fast path: check cached write index (no atomic, no cross-core traffic)
 *    Slow path: refresh cache with acquire load of producer's write index
 *    (acquire pairs with producer's release, ensuring slot data is visible)
 *    If still empty: nothing to consume (return false)
 * 4. Copy slot data out, then publish new read index with release store
 *    (release tells producer this slot is free to overwrite) */
bool ringbuf_pop(RingBuf *rb, PacketEvent *out) {
  size_t readIdx = atomic_load_explicit(&rb->read, memory_order_relaxed);
  size_t nextReadIdx = readIdx + 1;

  if (nextReadIdx == rb->capacity)
    nextReadIdx = 0;

  if (readIdx == rb->write_cache) {
    rb->write_cache = atomic_load_explicit(&rb->write, memory_order_acquire);
    if (readIdx == rb->write_cache)
      return false;
  }

  memcpy(out, &rb->slots[readIdx], sizeof(PacketEvent));
  atomic_store_explicit(&rb->read, nextReadIdx, memory_order_release);
  return true;
}
