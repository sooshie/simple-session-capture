#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "hash.h"

static struct hash_bucket *hash_lookup_fast(struct hash *hash, struct hash_bucket *bucket,
	const void *key, uint32_t hv);

static int hash_remove_fast(struct hash *hash,
	struct hash_bucket *bucket, const void *key, uint32_t hv);

static void hash_add_fast(struct hash *hash, struct hash_bucket *bucket, 
	const void *key, uint32_t hv, void *value);

static uint32_t hash_value (const struct hash *hash, const void *key)
{
	return (*hash->hash_function)(key, hash->iv);
}

#ifdef HASH_TEST
static uint32_t word_hash_function (const void *key, uint32_t iv)
{
	const char *str = (const char *) key;
	const int len = strlen (str);
	return hash_func((const uint8_t *)str, len, iv);
}

static int word_compare_function(const void *key1, const void *key2)
{
	return strcmp((const char *)key1, (const char *)key2) == 0;
}
#endif /* HASH_TEST */

struct hash *hash_init(const int n_buckets, const uint32_t iv, 
	uint32_t (*hash_function)(const void *key, uint32_t iv),
	int (*compare_function)(const void *key1, const void *key2))
{
	struct hash *h;
	int i;

	// must be power of 2
	if(n_buckets & (n_buckets - 1))
		return NULL;

	h = (struct hash *) malloc(sizeof(struct hash));
	h->nbuckets = n_buckets;
	h->nelem = 0;
	h->mask = h->nbuckets - 1;
	h->hash_function = hash_function;
	h->compare_function = compare_function;
	h->iv = iv;
	h->buckets = calloc(h->nbuckets, sizeof(struct hash_bucket));
	for (i = 0; i < h->nbuckets; ++i)
	{
		INIT_LIST_HEAD(&h->buckets[i].list);
	}
	return h;
}

void hash_free(struct hash *hash)
{
	int i;
	struct list_head *pos, *next;
	for (i = 0; i < hash->nbuckets; ++i)
	{
		struct hash_bucket *bucket;
		list_for_each_safe(pos, next, &hash->buckets[i].list)
		{
			bucket = list_entry(pos, struct hash_bucket, list);
//			printf("free elem (%p,%p)\n", bucket->key, bucket->value);

			list_del(pos);
			free(bucket);
		}
	}
	free (hash);
}

void *hash_lookup(struct hash *hash, const void *key)
{
	void *ret = NULL;
	uint32_t hv = hash_value (hash, key);
	struct hash_bucket *res;
	struct hash_bucket *bucket = &hash->buckets[hv & hash->mask];

	res = hash_lookup_fast(hash, bucket, key, hv);
	if (res)
		ret = res->value;

	return ret;
}

struct hash_bucket *hash_first(struct hash *hash)
{
	int i;
	struct hash_bucket *bucket;

	if(hash->nelem <= 0)
		return 0;

	for(i = 0; i < hash->nbuckets; ++i)
	{
		struct list_head *pos;
		bucket = &hash->buckets[i];

		list_for_each(pos, &bucket->list)
		{
			return list_entry(pos, struct hash_bucket, list);
		}
	}
	return NULL;
}

int hash_remove(struct hash *hash, const void *key)
{
	uint32_t hv;
	struct hash_bucket *bucket;
	int ret;

	hv = hash_value (hash, key);
	bucket = &hash->buckets[hv & hash->mask];
	ret = hash_remove_fast (hash, bucket, key, hv);

	return ret;
}

static struct hash_bucket *hash_lookup_fast(struct hash *hash, struct hash_bucket *bucket, 
	const void *key, uint32_t hv)
{
	struct hash_bucket *curr;
	struct list_head *pos;

	list_for_each(pos, &bucket->list)
	{
		curr = list_entry(pos, struct hash_bucket, list);
		if (hv == curr->hash_value && (*hash->compare_function)(key, curr->key))
		{
			return curr;
		}
	}

	return NULL;
}

static int hash_remove_fast (struct hash *hash, struct hash_bucket *bucket, const void *key, uint32_t hv)
{
	struct hash_bucket *curr;
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &bucket->list)
	{
		curr = list_entry(pos, struct hash_bucket, list);
		if (hv == curr->hash_value && (*hash->compare_function)(key, curr->key))
		{
			list_del(pos);
			free(curr);
			--hash->nelem;

			return 1;
		}
	}

	return 0;
}

int hash_add(struct hash *hash, const void *key, void *value, int replace)
{
	uint32_t hv;
	struct hash_bucket *bucket, *curr;
	int ret = 0;

	hv = hash_value (hash, key);
	bucket = &hash->buckets[hv & hash->mask];

	if((curr = hash_lookup_fast (hash, bucket, key, hv)))
	{
		if (replace)
		{
			curr->value = value;
			ret = 1;
		}
	}
	else
	{
		hash_add_fast (hash, bucket, key, hv, value);
		ret = 1;
	}

	return ret;
}

static void hash_add_fast(struct hash *hash,struct hash_bucket *bucket, const void *key, uint32_t hv, void *value)
{
	struct hash_bucket *curr;

	//printf("%s (%p,%p)\n", __FUNCTION__, key, value);

	curr = (struct hash_bucket *) malloc(sizeof(struct hash_bucket));
	curr->value = value;
	curr->key = key;
	curr->hash_value = hv;
	INIT_LIST_HEAD(&curr->list);
	list_add_tail(&curr->list, &bucket->list);
	++hash->nelem;
}

void hash_for_each(struct hash *hash, void (*callback)(const void *, void *, uint32_t))
{
	int i;
	struct list_head *pos;
	struct hash_bucket *bucket, *curr;

//	printf("%s\n", __FUNCTION__);

	for(i = 0; i < hash->nbuckets; ++i)
	{
		bucket = &hash->buckets[i];
		list_for_each(pos, &bucket->list)
		{
			curr = list_entry(pos, struct hash_bucket, list);
			(*callback)(curr->key, curr->value, curr->hash_value);
		}
	}
	printf("\n");
}

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 32-bit value
  k     : the key (the unaligned variable-length array of bytes)
  len   : the length of the key, counting by bytes
  level : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Every 1-bit and 2-bit delta achieves avalanche.
About 36+6len instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (uint8_t **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

See http://burlteburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^32 is
acceptable.  Do NOT use for cryptographic purposes.

--------------------------------------------------------------------

mix -- mix 3 32-bit values reversibly.
For every delta with one or two bit set, and the deltas of all three
  high bits or all three low bits, whether the original value of a,b,c
  is almost all zero or is uniformly distributed,
* If mix() is run forward or backward, at least 32 bits in a,b,c
  have at least 1/4 probability of changing.
* If mix() is run forward, every bit of c will change between 1/3 and
  2/3 of the time.  (Well, 22/100 and 78/100 for some 2-bit deltas.)
mix() was built out of 36 single-cycle latency instructions in a 
  structure that could supported 2x parallelism, like so:
      a -= b; 
      a -= c; x = (c>>13);
      b -= c; a ^= x;
      b -= a; x = (a<<8);
      c -= a; b ^= x;
      c -= b; x = (b>>13);
      ...
  Unfortunately, superscalar Pentiums and Sparcs can't take advantage 
  of that parallelism.  They've also turned some of those single-cycle
  latency instructions into multi-cycle latency instructions.  Still,
  this is the fastest good hash I could find.  There were about 2^^68
  to choose from.  I only looked at a billion or so.

James Yonan Notes:

* This function is faster than it looks, and appears to be
  appropriate for our usage in OpenVPN which is primarily
  for hash-table based address lookup (IPv4, IPv6, and Ethernet MAC).
  NOTE: This function is never used for cryptographic purposes, only
  to produce evenly-distributed indexes into hash tables.

* Benchmark results: 11.39 machine cycles per byte on a P2 266Mhz,
                     and 12.1 machine cycles per byte on a
                     2.2 Ghz P4 when hashing a 6 byte string.
--------------------------------------------------------------------
*/

#define mix(a,b,c)               \
{                                \
  a -= b; a -= c; a ^= (c>>13);  \
  b -= c; b -= a; b ^= (a<<8);   \
  c -= a; c -= b; c ^= (b>>13);  \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16);  \
  c -= a; c -= b; c ^= (b>>5);   \
  a -= b; a -= c; a ^= (c>>3);   \
  b -= c; b -= a; b ^= (a<<10);  \
  c -= a; c -= b; c ^= (b>>15);  \
}

uint32_t hash_func (const uint8_t *k, uint32_t length, uint32_t initval)
{
  uint32_t a, b, c, len;

  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;	     /* the golden ratio; an arbitrary value */
  c = initval;		     /* the previous hash value */

   /*---------------------------------------- handle most of the key */
  while (len >= 12)
    {
      a += (k[0] + ((uint32_t) k[1] << 8)
	         + ((uint32_t) k[2] << 16)
	         + ((uint32_t) k[3] << 24));
      b += (k[4] + ((uint32_t) k[5] << 8)
	         + ((uint32_t) k[6] << 16)
	         + ((uint32_t) k[7] << 24));
      c += (k[8] + ((uint32_t) k[9] << 8)
	         + ((uint32_t) k[10] << 16)
	         + ((uint32_t) k[11] << 24));
      mix (a, b, c);
      k += 12;
      len -= 12;
    }

   /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch (len)		    /* all the case statements fall through */
    {
    case 11:
      c += ((uint32_t) k[10] << 24);
    case 10:
      c += ((uint32_t) k[9] << 16);
    case 9:
      c += ((uint32_t) k[8] << 8);
      /* the first byte of c is reserved for the length */
    case 8:
      b += ((uint32_t) k[7] << 24);
    case 7:
      b += ((uint32_t) k[6] << 16);
    case 6:
      b += ((uint32_t) k[5] << 8);
    case 5:
      b += k[4];
    case 4:
      a += ((uint32_t) k[3] << 24);
    case 3:
      a += ((uint32_t) k[2] << 16);
    case 2:
      a += ((uint32_t) k[1] << 8);
    case 1:
      a += k[0];
      /* case 0: nothing left to add */
    }
  mix (a, b, c);
   /*-------------------------------------- report the result */
  return c;
}

#ifdef HASH_TEST

void word_print(const void *key, void *value, uint32_t hval)
{	
	printf("[0x%x,%s,%s]", hval, (const char*)key, (const char*)value);
}

static void test()
{
	int rc;
	char *key = "abc";
	char *val = "hbdkqjebdjbj$65_f";
	char *xval;
	char *key1 = "er3";
	char *val1 = "Hjjg%%^tgs";
	char *xval1;

	char *key2 = "scs";
	char *val2 = "u9-u8h";
	char *xval2;

	struct hash *h;
	struct hash_bucket *bucket;

	h = hash_init (2, 1, word_hash_function, word_compare_function);
	if(!h)
	{
		return;
	}

	printf("nelems: %d, nbuckets: %d, mask: %x\n", h->nelem, h->nbuckets, h->mask);
	hash_add(h, key, val, 0);
	printf("nelems: %d, nbuckets: %d, mask: %x\n", h->nelem, h->nbuckets, h->mask);
	xval = hash_lookup(h, key);
	printf("lookup: %p (%p), (%s,%s)\n", xval, val, xval, val);

	hash_add(h, key1, val1, 0);
	printf("nelems: %d, nbuckets: %d, mask: %x\n", h->nelem, h->nbuckets, h->mask);
	xval1 = hash_lookup(h, key1);
	printf("lookup: %p (%p), (%s,%s)\n", xval1, val1, xval1, val1);

	hash_add(h, key2, val2, 0);
	printf("nelems: %d, nbuckets: %d, mask: %x\n", h->nelem, h->nbuckets, h->mask);
	xval2 = hash_lookup(h, key2);
	printf("lookup: %p (%p), (%s,%s)\n", xval2, val2, xval2, val2);

	hash_for_each(h, &word_print);

	if(1)
	{
		// free all sessions
		while((bucket = hash_first(h)))
		{
			printf("releasing (%s,%s)\n", bucket->key, bucket->value);
			hash_remove(h, bucket->key);
		}
	}

	hash_free(h);
}

int main(int argc, char **argv)
{
	printf("start\n");
	test();
	printf("finish\n");
	return 0;
}

#endif
