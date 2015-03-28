#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <sys/uio.h> // for struct iovec
#include <pthread.h>
#else
struct iovec
{
	void   *iov_base;
	size_t iov_len;
};
#endif

#include "ring_buffer.h"

typedef struct ring_buffer
{
	uint8_t     *buf;
	rbuf_size_t capacity;
	rbuf_size_t nfree;
	uint8_t     wrapped;

	// locked region start
	uint8_t  *lptr;
	// read pointer
	uint8_t  *rptr;
	// write pointer
	uint8_t  *wptr;

#ifndef _WIN32
	pthread_mutex_t  mutex;
	pthread_cond_t   cond; 	
#endif

} ring_buffer_t;

static void ring_buffer_print(ring_buffer_t *rbuf);

#define ring_buffer_check(rbuf) \
	do {   \
		if((rbuf->rptr < rbuf->wptr && rbuf->wrapped) || (rbuf->rptr > rbuf->wptr && !rbuf->wrapped)) \
		{ \
			printf("%s:%d invariant failure\n", __FUNCTION__, __LINE__); \
			ring_buffer_print(rbuf);  \
		} \
	} while(0) 

ring_buffer_t *ring_buffer_alloc(rbuf_size_t capacity)
{
	ring_buffer_t *rbuf;

	if(!(rbuf = (ring_buffer_t *)malloc(sizeof(ring_buffer_t))))
		return NULL;

	memset(rbuf, '\0', sizeof(*rbuf));

	if(!(rbuf->buf = (uint8_t*)malloc(capacity)))
		goto fail__;
#ifndef _WIN32
	pthread_mutex_init(&rbuf->mutex, NULL);
	pthread_cond_init(&rbuf->cond, NULL);
#endif
	rbuf->nfree = capacity;
	rbuf->capacity = capacity;
	rbuf->rptr = rbuf->buf;
	rbuf->wptr = rbuf->buf;

	return rbuf;

fail__:

	ring_buffer_free(rbuf);
	return NULL;
}

void ring_buffer_free(ring_buffer_t *rbuf)
{
	if(rbuf)
	{
		if(rbuf->buf) free(rbuf->buf);
#ifndef _WIN32
		pthread_mutex_destroy(&rbuf->mutex);
		pthread_cond_destroy(&rbuf->cond);
#endif
		free(rbuf);
	}
}

rbuf_size_t ring_buffer_capacity(ring_buffer_t *rbuf)
{
	return rbuf->capacity;
}

rbuf_size_t ring_buffer_size(struct ring_buffer *rbuf)
{
	return rbuf->capacity - rbuf->nfree;

/*
	if(rbuf->wrapped)
		return (rbuf->buf + rbuf->capacity - rbuf->rptr) + (rbuf->wptr - rbuf->buf);

	return rbuf->wptr - rbuf->rptr;
*/
}

rbuf_size_t ring_buffer_available(struct ring_buffer *rbuf)
{
	return rbuf->nfree;
}

int ring_buffer_empty(struct ring_buffer *rbuf)
{
	if(!rbuf->wrapped && (rbuf->rptr == rbuf->wptr))
		return 1;

	return 0;
}

void ring_buffer_clear(ring_buffer_t *rbuf)
{
	rbuf->nfree = rbuf->capacity;
	rbuf->rptr  = rbuf->buf;
	rbuf->wptr  = rbuf->buf;
	rbuf->lptr  = NULL;
	rbuf->wrapped  = 0;
}

int ring_buffer_lock(ring_buffer_t *rbuf)
{
#ifndef _WIN32
	return pthread_mutex_lock(&rbuf->mutex);
#else
	return 0;
#endif

}

int ring_buffer_trylock(ring_buffer_t *rbuf)
{
#ifndef _WIN32
	return pthread_mutex_trylock(&rbuf->mutex);
#else
	return 0;
#endif
}

int ring_buffer_unlock(ring_buffer_t *rbuf)
{
#ifndef _WIN32
	return pthread_mutex_unlock(&rbuf->mutex);
#else
	return 0;
#endif
}

int ring_buffer_wait(struct ring_buffer *rbuf)
{
#ifndef _WIN32
	return pthread_cond_wait(&rbuf->cond, &rbuf->mutex);
#else
	return 0;
#endif
}

int ring_buffer_timedwait(struct ring_buffer *rbuf, const struct timespec *ts)
{
#ifndef _WIN32
	return pthread_cond_timedwait(&rbuf->cond, &rbuf->mutex, ts);
#else
	return 0;
#endif
}

int ring_buffer_notify(struct ring_buffer *rbuf)
{
#ifndef _WIN32
	return pthread_cond_signal(&rbuf->cond);
#else
	return 0;
#endif
}

int ring_buffer_write(ring_buffer_t *rbuf, const uint8_t *buf, uint32_t size)
{
	rbuf_size_t part_size;
	uint8_t     *uptr;

	ring_buffer_check(rbuf);

	if(rbuf->nfree < size)
		return -1;

	uptr = rbuf->buf + rbuf->capacity;

	if(rbuf->wptr + size >= uptr)
	{
		if(rbuf->wrapped)
		{
			printf("%s invariant failure\n", __FUNCTION__);
			ring_buffer_print(rbuf);
			return -1;
		}

		part_size = uptr - rbuf->wptr;
		memcpy(rbuf->wptr, buf, part_size);
		buf+= part_size;
		memcpy(rbuf->buf, buf, size - part_size);

		rbuf->wrapped = 1;
		rbuf->wptr = rbuf->buf + (size - part_size);
		rbuf->nfree-= size;
	}
	else
	{
		memcpy(rbuf->wptr, buf, size);
		rbuf->wptr+= size;
		rbuf->nfree-= size;
	}

	return 0;
}

int ring_buffer_read(ring_buffer_t *rbuf, uint8_t *buf, uint32_t size, int rdonly)
{
	rbuf_size_t part_size;
	uint8_t     *uptr;

	if(rbuf->capacity < rbuf->nfree + size)
		return -1;

	uptr = rbuf->buf + rbuf->capacity;
	if(rbuf->rptr + size >= uptr)
	{
		if(!rbuf->wrapped)
		{
			printf("%s invariant failure\n", __FUNCTION__);
			return -1;
		}

		part_size = uptr - rbuf->rptr;
		memcpy(buf, rbuf->rptr, part_size);
		buf+= part_size;
		memcpy(buf, rbuf->buf, size - part_size);

		if(!rdonly)
		{
			rbuf->wrapped = 0;
			rbuf->rptr = rbuf->buf + (size - part_size);
			rbuf->nfree+= size;
		}
	}
	else
	{
		memcpy(buf, rbuf->rptr, size);
		if(!rdonly)
		{
			rbuf->rptr+= size;
			rbuf->nfree+= size;
		}
	}

	return 0;
}

static int ring_buffer_dist(ring_buffer_t *rbuf, uint8_t *p0, uint8_t *p1)
{
	if(rbuf->wrapped)
	{
		return (p0 + rbuf->capacity - p1);
	}
	else
	{
		return (p0 - p1);
	}
}

static void ring_buffer_print(ring_buffer_t *rbuf)
{
	printf("w: %d, free: %lu, l: %lu, r: %lu, w: %lu\n",
		rbuf->wrapped, rbuf->nfree,
		(rbuf->lptr ? rbuf->lptr - rbuf->buf : -1),
		rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf);
}

static void iovec_print(ring_buffer_t *rbuf, const struct iovec region[2])
{
	printf("iovec b0: %lu, l0: %zu, b1: %lu, l1: %zu\n", 
	(uint8_t*)region[0].iov_base - rbuf->buf, region[0].iov_len,
	(region[1].iov_base ? (uint8_t*)region[1].iov_base - rbuf->buf : -1), region[1].iov_len);
}

#define REPORT_ERROR(rbuf, region) \
	do { \
		printf("%s:%d\n", __FUNCTION__, __LINE__); \
		ring_buffer_print(rbuf); \
		iovec_print(rbuf, region); \
	} while(0);

int ring_buffer_region_acquire(ring_buffer_t *rbuf, struct iovec region[2])
{
	rbuf_size_t part_size;
	uint8_t     *uptr;

	ring_buffer_check(rbuf);

	if(rbuf->capacity < rbuf->nfree + region[0].iov_len)
	{
		REPORT_ERROR(rbuf, region);
		return -1;
	}

	uptr = rbuf->buf + rbuf->capacity;
	if(rbuf->rptr + region[0].iov_len >= uptr)
	{
		if(!rbuf->wrapped)
		{
			printf("%s invariant failure\n", __FUNCTION__);
			REPORT_ERROR(rbuf, region);
			return -1;
		}
		part_size = uptr - rbuf->rptr;

		region[1].iov_len  = region[0].iov_len - part_size;
		region[1].iov_base = (region[1].iov_len ? rbuf->buf : NULL);
		region[0].iov_base = rbuf->rptr;
		region[0].iov_len  = part_size;

		if(!rbuf->lptr) 
			rbuf->lptr = rbuf->rptr;

		rbuf->wrapped = 1;
		rbuf->rptr = rbuf->buf + region[1].iov_len;
	}
	else
	{
		region[0].iov_base = rbuf->rptr;

		if(!rbuf->lptr) 
			rbuf->lptr = rbuf->rptr;

		rbuf->rptr+= region[0].iov_len;

	}

	return 0;
}

int ring_buffer_region_release(ring_buffer_t *rbuf, const struct iovec region[2])
{
	uint8_t  *uptr;

	ring_buffer_check(rbuf);

	if(!rbuf->lptr)
		return 0;

	uptr = rbuf->buf + rbuf->capacity;

	if(region[0].iov_base != rbuf->lptr 
		|| (region[1].iov_base && region[0].iov_base + region[0].iov_len != uptr))
	{
		REPORT_ERROR(rbuf, region);
		return RING_BUFFER_EINVAL;
	}

	if(region[1].iov_base)
	{
		if(region[1].iov_base != rbuf->buf 
			|| (uint8_t*)region[1].iov_base + region[1].iov_len > rbuf->rptr)
		{
			REPORT_ERROR(rbuf, region);
			return RING_BUFFER_EINVAL;
		}

		if(rbuf->rptr == (uint8_t*)region[1].iov_base + region[1].iov_len)
		{
			rbuf->lptr = NULL;
		}
		else
		{
			rbuf->lptr = ((uint8_t*)region[1].iov_base + region[1].iov_len);
		}
		rbuf->nfree+= (region[0].iov_len + region[1].iov_len);
		rbuf->wrapped = 0;
	}
	else
	{

		if(ring_buffer_dist(rbuf, rbuf->rptr, (uint8_t*)region[0].iov_base) < region[0].iov_len)
		{
			REPORT_ERROR(rbuf, region);
			return RING_BUFFER_EINVAL;
		}

		if(rbuf->rptr == (uint8_t*)region[0].iov_base + region[0].iov_len)
		{
			rbuf->lptr = NULL;
		}
		else
		{
			rbuf->lptr+= region[0].iov_len;
			if(rbuf->lptr >= uptr)
			{
				rbuf->wrapped = 0;			
				rbuf->lptr-= rbuf->capacity;
			}
		}
		rbuf->nfree+= region[0].iov_len;
	}

	return 0;
}

#ifdef RBUFFER_TEST

static void test()
{
	int len, rc;
	uint32_t capacity = 10;
	struct ring_buffer *rbuf;
	struct iovec data[4];
	uint8_t buf[128];
	struct iovec region1[2];
	struct iovec region2[2];

	rbuf = ring_buffer_alloc(capacity);
	if(!rbuf)
		return;

	memset(&data, '\0', sizeof(data));
	memset(&region1, '\0', sizeof(region1));
	memset(&region2, '\0', sizeof(region2));

	printf("writing, nfree: %d\n", rbuf->nfree);
	data[0].iov_base = "abcdefgh";
	data[0].iov_len = strlen((char*)data[0].iov_base);

	if(ring_buffer_write(rbuf, data[0].iov_base, data[0].iov_len) < 0)
	{
		printf("%d ring_buffer_write failed\n", __LINE__);
		goto fin__;
	}

	len = data[0].iov_len;
	printf("reading, nfree: %d\n", rbuf->nfree);
	if(ring_buffer_read(rbuf, buf, len, 0) < 0)
	{
		printf("%d ring_buffer_read failed\n", __LINE__);
		goto fin__;
	}
	printf("read: \'%.*s\'\n", len, buf);
	printf("nfree: %d\n", rbuf->nfree);

	printf("writing, nfree: %d, r: %d, w: %d\n", rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf);
	data[1].iov_base = "ZXCVBN";
	data[1].iov_len = strlen((char*)data[1].iov_base);

	if(ring_buffer_write(rbuf, data[1].iov_base, data[1].iov_len) < 0)
	{
		printf("%d ring_buffer_write failed\n", __LINE__);
		goto fin__;
	}

	len = data[1].iov_len;
	printf("reading, nfree: %d, r: %d, w: %d\n", rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf);
	if(ring_buffer_read(rbuf, buf, len, 0) < 0)
	{
		printf("%d ring_buffer_read failed\n", __LINE__);
		goto fin__;
	}
	printf("read: \'%.*s\'\n", len, buf);
	printf("writing nfree: %d, r: %d, w: %d\n", rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf);

	data[2].iov_base = "12Rfg3xxYv";
	data[2].iov_len = strlen((char*)data[2].iov_base);

	if(ring_buffer_write(rbuf, data[2].iov_base, data[2].iov_len) < 0)
	{
		printf("%d ring_buffer_write failed\n", __LINE__);
		goto fin__;
	}

	len = data[2].iov_len;
	printf("reading, nfree: %d, r: %d, w: %d\n", rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf);
	if(ring_buffer_read(rbuf, buf, len, 0) < 0)
	{
		printf("%d ring_buffer_read failed\n", __LINE__);
		goto fin__;
	}
	printf("read: \'%.*s\'\n", len, buf);
	printf("nfree: %d, r: %d, w: %d\n", rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf);

	data[3].iov_base = "fgDswert4";
	data[3].iov_len = strlen((char*)data[3].iov_base);

	if(ring_buffer_write(rbuf, data[3].iov_base, data[3].iov_len) < 0)
	{
		printf("%d ring_buffer_write failed\n", __LINE__);
		goto fin__;
	}
	printf("write, nfree: %d, r: %d, w: %d, l: %d\n", 
		rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf, (rbuf->lptr ? rbuf->wptr - rbuf->buf : -1));

	region1[0].iov_len = 5;
	if(ring_buffer_region_acquire(rbuf, region1) != 0)
	{
		printf("%d ring_buffer_region_acquire failed\n", __LINE__);
		goto fin__;
	}
	printf("acquire: \'%.*s\'\n", region1[0].iov_len, region1[0].iov_base);
	printf("nfree: %d, r: %d, w: %d, l: %d\n", 
		rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf, (rbuf->lptr ? rbuf->lptr - rbuf->buf : -1));

	region2[0].iov_len = 4;
	if(ring_buffer_region_acquire(rbuf, region2) != 0)
	{
		printf("%d ring_buffer_region_acquire failed\n", __LINE__);
		goto fin__;
	}
	printf("acquire: \'%.*s\' \'%.*s\'\n", region2[0].iov_len, region2[0].iov_base, region2[1].iov_len, region2[1].iov_base);
	printf("nfree: %d, r: %d, w: %d, l: %d\n", 
		rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf, (rbuf->lptr ? rbuf->lptr - rbuf->buf : -1));

	if(ring_buffer_region_release(rbuf, region1) != 0)
	{
		printf("%d ring_buffer_region_release failed\n", __LINE__);
		goto fin__;
	}
	printf("release nfree: %d, r: %d, w: %d, l: %d\n", 
		rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf, (rbuf->lptr ? rbuf->lptr - rbuf->buf : -1));

	if(ring_buffer_region_release(rbuf, region2) != 0)
	{
		printf("%d ring_buffer_region_release failed\n", __LINE__);
		goto fin__;
	}
	printf("release nfree: %d, r: %d, w: %d, l: %d\n", 
		rbuf->nfree, rbuf->rptr - rbuf->buf, rbuf->wptr - rbuf->buf, (rbuf->lptr ? rbuf->lptr - rbuf->buf : -1));



fin__:
	ring_buffer_free(rbuf);
}

#include <errno.h>

static void test_file(const char *infile, const char *outfile)
{
	FILE *infp, *outfp = NULL;
	int len, rc;
	uint32_t capacity = 256;
	struct ring_buffer *rbuf = NULL;
	// buffer size is mutually prime with ring buffer capacity for better testing
	uint8_t inbuf[127];
	uint8_t outbuf[127];

	printf("\'%s\'->\'%s\'\n", infile, outfile);

	if(!(infp = fopen(infile, "rb")))
	{
		printf("couldn't open file \'%s\': %s\n", infile, strerror(errno));
		return;
	}

	if(!(outfp = fopen(outfile, "wb")))
	{
		printf("couldn't open file \'%s\': %s\n", outfile, strerror(errno));
		goto fin__;
	}

	rbuf = ring_buffer_alloc(capacity);
	if(!rbuf)
	{
		printf("couldn't allocate ring buffer, capacity: %d\n", capacity);
		goto fin__;
	}

	while(1)
	{
		if((len = fread(inbuf, 1, sizeof(inbuf), infp)) <= 0)
			break;

		if(ring_buffer_write(rbuf, inbuf, len) < 0)
		{
			printf("ring_buffer_write failed\n");
			goto fin__;
		}

		if(ring_buffer_read(rbuf, outbuf, len, 0) < 0)
		{
			printf("ring_buffer_read failed\n");
			goto fin__;
		}

		if((len = fwrite(outbuf, 1, len, outfp)) <= 0)
		{
			printf("fwrite failed, file: \'%s\', error: %s\n", outfile, strerror(errno));
			goto fin__;
		}
	}

fin__:
	if(infp)  fclose(infp);
	if(outfp) fclose(outfp);
	ring_buffer_free(rbuf);
}

int main(int argc, char **argv)
{
	printf("start\n");
//	test();
	if(argc > 2)
		test_file(argv[1], argv[2]);

	printf("finish\n");
	return 0;
}

#endif /* RBUFFER_TEST */


