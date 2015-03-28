#ifndef _RING_BUFFER_H__
#define _RING_BUFFER_H__

#include <inttypes.h>

#define RING_BUFFER_EINVAL  -2

typedef uint64_t rbuf_size_t;

struct ring_buffer;
struct ring_buffer *ring_buffer_alloc(rbuf_size_t capacity);
void ring_buffer_free(struct ring_buffer *rbuf);
void ring_buffer_clear(struct ring_buffer *rbuf);

// synchronization methods
int ring_buffer_lock(struct ring_buffer *rbuf);
int ring_buffer_trylock(struct ring_buffer *rbuf);
int ring_buffer_unlock(struct ring_buffer *rbuf);
int ring_buffer_notify(struct ring_buffer *rbuf);
int ring_buffer_wait(struct ring_buffer *rbuf);
struct timespec;
int ring_buffer_timedwait(struct ring_buffer *rbuf, const struct timespec *ts);

// rw
int ring_buffer_write(struct ring_buffer *rbuf, const uint8_t *msg, uint32_t size);
int ring_buffer_read(struct ring_buffer *rbuf, uint8_t *msg, uint32_t size, int rdonly);

// zero copy stuff
struct iovec;
int ring_buffer_region_acquire(struct ring_buffer *rbuf, struct iovec region[2]);
int ring_buffer_region_release(struct ring_buffer *rbuf, const struct iovec region[2]);

rbuf_size_t ring_buffer_capacity(struct ring_buffer *rbuf);
rbuf_size_t ring_buffer_size(struct ring_buffer *rbuf);
rbuf_size_t ring_buffer_available(struct ring_buffer *rbuf);
int ring_buffer_empty(struct ring_buffer *rbuf);


#endif /* _RING_BUFFER_H__ */

