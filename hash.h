#ifndef _HASH_UTILS_H__
#define _HASH_UTILS_H__

#include <inttypes.h>
#include "list.h"

struct hash_bucket
{
	void       *value;
	const void *key;
	uint32_t   hash_value;
	struct list_head list;
};

struct hash
{
	int nbuckets;
	int nelem;
	int mask;
	uint32_t iv;
	uint32_t (*hash_function)(const void *key, uint32_t iv);
	int (*compare_function)(const void *key1, const void *key2);
	struct hash_bucket *buckets;
};

uint32_t hash_func(const uint8_t *k, uint32_t length, uint32_t initval);

struct hash *hash_init(const int nbuckets, const uint32_t iv,
	uint32_t (*hash_function)(const void *key, uint32_t iv),
	int (*compare_function)(const void *key1, const void *key2));

void hash_free(struct hash *hash);
int  hash_add(struct hash *hash, const void *key, void *value, int replace);
void *hash_lookup(struct hash *hash, const void *key);
int  hash_remove(struct hash *hash, const void *key);
struct hash_bucket *hash_first(struct hash *hash);

void hash_for_each(struct hash *hash, void (*callback)(const void *, void *, uint32_t));

#endif /* _HASH_UTILS_H__ */

