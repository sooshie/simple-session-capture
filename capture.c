#include <pcap.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <aio.h>
#include <sched.h>
#include <sys/syscall.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/dccp.h>

#include "hash.h"
#include "ring_buffer.h"
#include "filehashmap.h"

//#define USE_AIO_
//#define USE_CPU_SCHED_

#define READER_CPU  0
#define WRITER_CPU  1

#define log_z(...)   printf(__VA_ARGS__)

#ifdef DEBUG
#define log_dbg(...) printf(__VA_ARGS__)
#else
#define log_dbg(...) do{} while(0)
#endif  /* DEBUG */

#define CLEAR(x)   memset (&(x), 0, sizeof(x))
#define SNAP_LEN 65535

#define HEADER_LEN (sizeof(struct pcap_pkthdr) - sizeof(struct timeval) + 8)

static const int version_sub = 2;
static const int version_minor = 7;
static const int version_major = 0;

// session limits
static uint32_t idle_timeout = 60;
static uint32_t idle_check_timeout = 5;
static uint64_t max_sess_length = 30*1024*1024;

// default ring buffer capacity
static const uint64_t rbuf_capacity  = 50*1024*1024;
// cache capacity must be lower than ring buffer capacity
static const uint32_t cache_capacity = 1024*1024;

typedef struct params
{
    const char *devname;
    const char *expr;
    const char *output_dir;
    uint64_t   rbuf_capacity;
    uint32_t   cache_capacity;

} params_t;

enum tcp_state
{
    TCP_STATE_CLOSED = 0,
    // skip SYN_* states
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT
};

enum session_state
{
    STATE_OPEN = 0,
    STATE_IDLE,
    STATE_CLOSING
};

typedef struct addr_tuple
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  proto;

} __attribute__ ((__packed__)) addr_tuple_t;

typedef struct session
{
    struct addr_tuple addr;
    // src/dst reversed
    struct addr_tuple addr2;
    struct timeval    start;
    struct timeval    access;
    uint64_t npackets;
    uint64_t nwritten;
    // logging descriptor
    int fd;
    struct aiocb aiocb;

    enum tcp_state     state;
    enum session_state statex;

    // list sorted by access time
    struct list_head list;

#ifdef DEBUG
    char filename[256];
#endif

} session_t;

typedef struct context
{
    pcap_t *handle;
    struct bpf_program fp;
    struct pcap_stat pcs;
    struct pcap_file_header fh;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct hash *sess_hash;
    // idle session timeout
//    int  idle_timeout;
    struct timeval last_gc;
//    time_t last_gc;
    uint64_t npackets;

    pthread_t wrid;
    struct ring_buffer *rbuf;

    // capture cache to decrease lock contention
    struct
    {
        uint8_t *buf;
        size_t  size;
        size_t  capacity;
    } cache;

    // file IO
    uint8_t *currbuf;
    uint8_t *nextbuf;
    // simplest IO queue
    struct aiocb *pending_aio;

    // session list sorted by access time
    struct session *sessions;

} context_t;

static volatile int running = 1;
static volatile int writer_running = 1;
static context_t main_ctx;

static void addr_copy(struct addr_tuple *dst, struct addr_tuple *src)
{
    dst->proto    = src->proto;
    dst->src_addr = src->src_addr;
    dst->dst_addr = src->dst_addr;
    dst->src_port = src->src_port;
    dst->dst_port = src->dst_port;
}

static void addr_twisted_copy(struct addr_tuple *dst, struct addr_tuple *src)
{
    dst->proto    = src->proto;
    dst->src_addr = src->dst_addr;
    dst->dst_addr = src->src_addr;
    dst->src_port = src->dst_port;
    dst->dst_port = src->src_port;
}

static uint32_t addr_hash_function(const void *key, uint32_t iv)
{
    return hash_func(key, sizeof(struct addr_tuple), iv);
}

static int addr_compare_function(const void *key0, const void *key1)
{
    struct addr_tuple *addr0, *addr1;
    addr0 = (struct addr_tuple *)key0;
    addr1 = (struct addr_tuple *)key1;

    // return memcmp(key0, key1, sizeof(struct addr_tuple)) == 0;

    if(addr0->proto == addr1->proto 
        && addr0->src_addr == addr1->src_addr
        && addr0->dst_addr == addr1->dst_addr
        && addr0->src_port == addr1->src_port
        && addr0->dst_port == addr1->dst_port)
        return 1;

    return 0;
}

static const char *ipproto_str(uint8_t proto);

#ifdef DEBUG
static void addr_print(const void *key, void *value, uint32_t hval)
{
    struct addr_tuple const *addr = (struct addr_tuple const*)key;

    uint32_t src_addr = addr->src_addr;
    uint32_t dst_addr = addr->dst_addr;

    printf("[0x%x,%s_%u.%u.%u.%u.%u_%u.%u.%u.%u.%u,%p] ", 
        hval,
        ipproto_str(addr->proto),
        src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff,
        addr->src_port,
        dst_addr & 0xff, (dst_addr >> 8) & 0xff, (dst_addr >> 16) & 0xff, (dst_addr >> 24) & 0xff,
        addr->dst_port,
        value);
}

static const char *state_str(enum tcp_state state)
{
    switch(state)
    {
        case TCP_STATE_CLOSED:
            return "TCP_STATE_CLOSED";

        case TCP_STATE_ESTABLISHED:
            return "TCP_STATE_ESTABLISHED";

        case TCP_STATE_FIN_WAIT_1:
            return "TCP_STATE_FIN_WAIT_1";

        case TCP_STATE_FIN_WAIT_2:
            return "TCP_STATE_FIN_WAIT_2";

        case TCP_STATE_CLOSING:
            return "TCP_STATE_CLOSING";

        case TCP_STATE_CLOSE_WAIT:
            return "TCP_STATE_CLOSE_WAIT";

        case TCP_STATE_LAST_ACK:
            return "TCP_STATE_LAST_ACK";

        case TCP_STATE_TIME_WAIT:
            return "TCP_STATE_TIME_WAIT";

        default:
            break;
    }

    return "Unknown";
}
#endif /* DEBUG */

static int device_open(context_t *ctx, params_t *pp);
static int device_close(context_t *ctx);
static int context_open(context_t *ctx, params_t *pp);
static int context_close(context_t *ctx);

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
static int  process_packet(context_t *ctx, uint8_t *buf, int len);

static session_t *session_lookup(context_t *ctx, struct addr_tuple *paddr);
static session_t *session_create(context_t *ctx, struct addr_tuple *paddr, const struct timeval *pnow);
static int session_fopen(context_t *ctx, session_t *sess);
static int session_fclose(context_t *ctx, session_t *sess);
static int session_close(context_t *ctx, session_t *sess);
static int session_free(context_t *ctx, session_t *sess);

static int session_write_packet(context_t *ctx, session_t *sess, const struct pcap_pkthdr *header, 
    struct addr_tuple *addr, uint8_t *buf, int len);
static int tcp_session_write_packet(context_t *ctx, session_t *sess, const struct pcap_pkthdr *header, 
    struct addr_tuple *addr, uint8_t *buf, int len);
static int udp_session_write_packet(context_t *ctx, session_t *sess, const struct pcap_pkthdr *header, 
    struct addr_tuple *addr, uint8_t *buf, int len);
static int session_write_packet_impl(context_t *ctx, session_t *sess, const struct pcap_pkthdr *header, 
    uint8_t *buf, int len);

static int session_is_full(context_t *ctx, session_t *sess);
static int session_is_expired(context_t *ctx, session_t *sess, struct timeval *pnow);

static int fetch_ip_address(struct addr_tuple *addr, struct iphdr *ip_hdr);

static void *writer_thread(void *arg);
static void set_cpu_affinity(int cpu_id);
static void flush_capture_cache(context_t *ctx);
static int  next_packet(context_t *ctx);
static int  run_gc(context_t *ctx);

static const char *ipproto_str(uint8_t proto)
{
    switch(proto)
    {
        case IPPROTO_TCP:
            return "tcp";

        case IPPROTO_UDP:
            return "udp";

        case IPPROTO_DCCP:
            return "dccp";

        case IPPROTO_ICMP:
            return "icmp";

        case IPPROTO_IGMP:
            return "igmp";

        case IPPROTO_IPIP:
            return "ipip";

        case IPPROTO_GRE:
            return "gre";

        case IPPROTO_IPV6:
            return "ipv6";

        case IPPROTO_ESP:
            return "esp";

        case IPPROTO_AH:
            return "ah";

        case IPPROTO_SCTP:
            return "sctp";

        default:
            break;
    }
    return "ip";
}

static void run(params_t *pp)
{
    void *ret;
    context_t *ctx = &main_ctx;

    set_cpu_affinity(READER_CPU);

    CLEAR(main_ctx);
    if(device_open(ctx, pp) < 0)
        goto fin__;

    if(context_open(ctx, pp) < 0)
        goto fin__;

    if(pthread_create(&ctx->wrid, NULL, &writer_thread, ctx) < 0)
    {
        log_z("couldn't create writer thread: %s\n", strerror(errno));
        goto fin__;
    }

    pcap_loop(ctx->handle, -1, got_packet, NULL);

    log_z("got quit signal, flushing cache...\n");
    flush_capture_cache(ctx);

    ring_buffer_lock(ctx->rbuf);
    writer_running = 0;
    ring_buffer_notify(ctx->rbuf);
    ring_buffer_unlock(ctx->rbuf);

    pthread_join(ctx->wrid, &ret);

    log_z("stat: %u packets received, %"PRIu64" saved, %u dropped\n", 
        ctx->pcs.ps_recv, ctx->npackets, ctx->pcs.ps_drop);

fin__:
    device_close(&main_ctx);
    context_close(&main_ctx);
}

static int fetch_ip_address(struct addr_tuple *addr, struct iphdr *ip_hdr)
{
    struct tcphdr   *tcp_hdr;
    struct udphdr   *udp_hdr;
    struct dccp_hdr *dccp_hdr;

    addr->src_addr = ip_hdr->saddr;
    addr->dst_addr = ip_hdr->daddr;
    addr->proto    = ip_hdr->protocol;

    switch(addr->proto)
    {
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr *)((uint8_t *)ip_hdr + sizeof(struct iphdr));
            addr->src_port = ntohs(tcp_hdr->source);
            addr->dst_port = ntohs(tcp_hdr->dest);
            break;

        case IPPROTO_UDP:
            udp_hdr = (struct udphdr *)((uint8_t *)ip_hdr + sizeof(struct iphdr));
            addr->src_port = ntohs(udp_hdr->source);
            addr->dst_port = ntohs(udp_hdr->dest);
            break;

        case IPPROTO_DCCP:
            dccp_hdr = (struct dccp_hdr *)((uint8_t *)ip_hdr + sizeof(struct iphdr));
            addr->src_port = ntohs(dccp_hdr->dccph_sport);
            addr->dst_port = ntohs(dccp_hdr->dccph_dport);
            break;

        default:
            addr->src_port = 0;
            addr->dst_port = 0;
            break;
    }

    return 0;
}

static void flush_capture_cache(context_t *ctx)
{
    int rc;
    struct ring_buffer *rbuf = ctx->rbuf;

    ring_buffer_lock(rbuf);
    if((rc = ring_buffer_write(rbuf, ctx->cache.buf, ctx->cache.size)) == 0) 
        ring_buffer_notify(rbuf);
    ring_buffer_unlock(rbuf);

    ctx->cache.size = 0;
    if(rc < 0)
        log_z("ring buffer is full, skip captured packet(s)\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    uint32_t  len;
    context_t *ctx = &main_ctx;
//    struct ring_buffer *rbuf = ctx->rbuf;

    if(!running)
    {
        pcap_breakloop(ctx->handle);
        if(pcap_stats(ctx->handle, &ctx->pcs) < 0)
        {
            log_z("pcap_stats failed: %s\n", pcap_geterr(ctx->handle));
            return;
        }
        return;
    }

    len = header->caplen + HEADER_LEN;

    // may happen for unreasonably small cache capacity
    if(len + ctx->cache.size > ctx->cache.capacity)
    {
        log_z("cache overflow, avail: %zu, capacity: %zu, packet len: %u\n", 
            ctx->cache.size, ctx->cache.capacity, len);

        exit(1);
    }

    uint8_t *ptr = ctx->cache.buf + ctx->cache.size; 
#ifdef __LP64__
    {
        struct timeval_32 
        {
            int tv_sec;
            int tv_usec;
        } tv32;
        tv32.tv_sec  = header->ts.tv_sec;
        tv32.tv_usec = header->ts.tv_usec;
        memcpy(ptr, (char *)&tv32, sizeof(tv32));
        ptr+= sizeof(tv32);
        memcpy(ptr, (char *)header + sizeof(struct timeval),
            sizeof(struct pcap_pkthdr) - sizeof(struct timeval));
        ptr+= (sizeof(struct pcap_pkthdr) - sizeof(struct timeval));
    }
#else
    memcpy(ptr, (char *)header, sizeof(struct pcap_pkthdr));
    ptr+= sizeof(struct pcap_pkthdr);
#endif /* __LP64__ */
    memcpy(ptr, (char *)packet, header->caplen);
    ctx->cache.size+= len;

    if(ctx->cache.size + /*SNAP_LEN*/ 3000 > ctx->cache.capacity)
        flush_capture_cache(ctx);
}

static void set_cpu_affinity(int cpu_id)
{
#ifdef USE_CPU_SCHED_

    int tid = syscall(SYS_gettid);
    cpu_set_t csmask;
    CPU_ZERO(&csmask);
    CPU_SET(cpu_id, &csmask);
    if(sched_setaffinity(tid, sizeof(cpu_set_t), &csmask) != 0)
    {
        log_z("could not set cpu affinity for CPU %d: %s\n", cpu_id, strerror(errno));
        }
#endif
}

#define ARRAY_LEN(a) (sizeof(a)/sizeof(a[0]))

static int next_packet(context_t *ctx)
{
    uint32_t len;
    struct ring_buffer *rbuf = ctx->rbuf;

    // extract capture length
    if(ring_buffer_read(rbuf, ctx->currbuf, 12, 1) < 0)
        return -1;

    len = *(uint32_t*)(ctx->currbuf + 8);
    // add header length
    len+= HEADER_LEN;
    if(ring_buffer_read(rbuf, ctx->currbuf, len, 0) < 0)
        return -1;

    return len;
}

static void *writer_thread(void *arg)
{
    context_t *ctx = (context_t *)arg;
    struct ring_buffer *rbuf = ctx->rbuf;
    int32_t len;
    struct timespec timeout;
    int gc = 0;
    uint8_t *outbuf;

    set_cpu_affinity(WRITER_CPU);

    if(!(outbuf = (uint8_t*)malloc(2 * SNAP_LEN)))
    {
        log_z("couldn't allocate writer buffer\n");
        exit(1);
    }
    ctx->currbuf = outbuf;
    ctx->nextbuf = outbuf + SNAP_LEN;

    while(1)
    {
        int err;

        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec+= 1;

        ring_buffer_lock(rbuf);
        while(writer_running && ring_buffer_empty(rbuf))
        {
            if((err = ring_buffer_timedwait(rbuf, &timeout)) && (err == ETIMEDOUT))
            {
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec+= 1;
            }

            if(timeout.tv_sec > ctx->last_gc.tv_sec + idle_check_timeout)
            {
                gc = 1;
                break;
            }
        }

        // process captured packets before quit
        if(!writer_running)
        {
            while(1)
            {
                if((len = next_packet(ctx)) < 0)
                {
                    // all packets processed
                    ring_buffer_unlock(rbuf);
                    break;
                }
                ring_buffer_unlock(rbuf);
                process_packet(ctx, ctx->currbuf, len);
                ring_buffer_lock(rbuf);
            }
            break;
        }

        if(gc)
        {
            int count;
            ring_buffer_unlock(rbuf);
            if((count = run_gc(ctx)) > 0)
                log_dbg("closed %d idle sessions\n", count);

            gc = 0;
            continue;
        }

        if((len = next_packet(ctx)) < 0)
        {
            ring_buffer_unlock(rbuf);
            log_z("internal error, ring buffer read failed\n");
            break;
        }
        ring_buffer_unlock(rbuf);
        process_packet(ctx, ctx->currbuf, len);
    }
    free(outbuf);
    log_z("writer thread terminated\n");

    return NULL;
}

static int wait_pending_aio(struct aiocb *cb)
{
    int rc;
    if((rc = aio_error(cb)))
    {
        if(rc == EINPROGRESS)
        {
            const struct aiocb *const aio_list[1] = {cb};
            if(aio_suspend(aio_list, 1, NULL) < 0)
            {
                log_z("aio_suspend: %s\n", strerror(errno));
                return -1;
            }
        }
        else
        {
            log_z("aio_error: %s, fd: %d, len: %zu, buf: %p\n",
                strerror(rc), cb->aio_fildes, cb->aio_nbytes, cb->aio_buf);

            return -1;
        }
    }
    if((rc = aio_return(cb)) < 0)
        log_z("aio_return error: %s\n", strerror(errno));
//    else
//        log_dbg("aio_return: %d, expected %zu\n", rc, cb->aio_nbytes);

    return rc;    
}

static int process_packet(context_t *ctx, uint8_t *buf, int len)
{
    uint8_t *packet;
    struct pcap_pkthdr pkt_hdr, *header = &pkt_hdr;

    struct ethhdr *eth_hdr;
    struct iphdr  *ip_hdr;

    struct addr_tuple addr;
    session_t *sess;

#ifdef __LP64__
    {
        pkt_hdr.ts.tv_sec  = *(uint32_t*)buf;
        pkt_hdr.ts.tv_usec = *(uint32_t*)(buf + 4);
        pkt_hdr.caplen     = *(uint32_t*)(buf + 8);
        pkt_hdr.len        = *(uint32_t*)(buf + 12);
    }
#else
    pkt_hdr = *(struct pcap_pkthdr *)buf;
#endif /* __LP64__ */
    packet = buf + HEADER_LEN;

    eth_hdr = (struct ethhdr *)packet;
    // skip non-IP packets
    if(ETH_P_IP != ntohs(eth_hdr->h_proto))
        return 0;

    ip_hdr = (struct iphdr *)(packet + sizeof(struct ethhdr));
    fetch_ip_address(&addr, ip_hdr);

    if(1 && addr.proto != IPPROTO_TCP)
    {
        char tmp[128];
        tmp[0] = '\0';

        snprintf(tmp, sizeof(tmp), "%s:%d ", 
            inet_ntoa(*(struct in_addr *)&addr.dst_addr), addr.dst_port);

        log_dbg("%s:%d -> %s\n", 
            inet_ntoa(*(struct in_addr *)&addr.src_addr), addr.src_port,
            tmp);
    }

    sess = session_lookup(ctx, &addr);
    if(!sess)
    {
#ifdef DEBUG
        hash_for_each(ctx->sess_hash, &addr_print);
#endif
        sess = session_create(ctx, &addr, &header->ts);
        if(!sess)
        {
            log_z("couldn't create new session\n");
            return -1;
        }
    }
#ifdef USE_AIO_
    // wait for pending file IO 
    if(ctx->pending_aio)
    {
        wait_pending_aio(ctx->pending_aio);
        ctx->pending_aio = NULL;
    }
#endif
    session_write_packet(ctx, sess, header, &addr, buf, len);

    // swap outbuf pointers
    {
        uint8_t *tmp = ctx->nextbuf;
        ctx->nextbuf = ctx->currbuf;
        ctx->currbuf = tmp;
    }
    // update position in access queue
    list_del(&sess->list);
    list_add_tail(&sess->list, &ctx->sessions->list);

    return 0;
}

// lookup and close expired sessions
static int run_gc(context_t *ctx)
{
    int count = 0;
    session_t *sess;
    struct list_head *pos, *next;
    struct timeval now;

    gettimeofday(&now, NULL);
    list_for_each_safe(pos, next, &ctx->sessions->list)
    {
        sess = list_entry(pos, session_t, list);
        if(!session_is_expired(ctx, sess, &now))
            break;

//        log_dbg("%s, free session %s\n", __FUNCTION__, sess->filename);
        session_free(ctx, sess);
        ++count;
    }
    ctx->last_gc = now;
//    log_dbg("%s, closed %d sessions\n", __FUNCTION__, count);

    return count;
}

static session_t *session_lookup(context_t *ctx, struct addr_tuple *paddr)
{
    session_t *sess;
    if((sess = hash_lookup(ctx->sess_hash, paddr)) == NULL)
        return NULL;

    return sess;
}

static session_t *session_create(context_t *ctx, struct addr_tuple *paddr, const struct timeval *pnow)
{
    session_t *sess;

    sess = (session_t *)malloc(sizeof(session_t));
    if(!sess)
        return NULL;

    addr_copy(&sess->addr, paddr);
    addr_twisted_copy(&sess->addr2, paddr);
    sess->npackets = 0;
    sess->nwritten = 0;
    sess->start = *pnow;
    sess->access = *pnow;
    sess->state = TCP_STATE_ESTABLISHED;
    sess->statex = STATE_OPEN;

    INIT_LIST_HEAD(&sess->list);

    if(session_fopen(ctx, sess) < 0)
    {
        free(sess);
        return NULL;
    }

//    log_dbg("%s %s\n", __FUNCTION__, sess->filename);

    // register <addr tuple,session>
    hash_add(ctx->sess_hash, &sess->addr,  sess, 0);
    hash_add(ctx->sess_hash, &sess->addr2, sess, 0);

    // add session to the end of access queue
    list_add_tail(&sess->list, &ctx->sessions->list);

    return sess;
}

static int session_fopen(context_t *ctx, session_t *sess)
{
    int flags;
    char filename[128];
        char temp[64];
        char fullpath[256];
    uint32_t src_addr, dst_addr;
    char* dir = NULL;

    if(sess->fd > 0)
        return 0;

    src_addr = sess->addr.src_addr;
    dst_addr = sess->addr.dst_addr;
    snprintf(filename, sizeof(filename), "%s_%lu.%06lu_%u.%u.%u.%u.%u_%u.%u.%u.%u.%u.pcap", 
        ipproto_str(sess->addr.proto),
        sess->start.tv_sec, sess->start.tv_usec / 1000,
        src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff,
        sess->addr.src_port,
        dst_addr & 0xff, (dst_addr >> 8) & 0xff, (dst_addr >> 16) & 0xff, (dst_addr >> 24) & 0xff,
        sess->addr.dst_port);

    snprintf(temp, sizeof(temp), "%u.%u.%u.%u.%u_%u.%u.%u.%u.%u", 
        src_addr & 0xff, (src_addr >> 8) & 0xff, (src_addr >> 16) & 0xff, (src_addr >> 24) & 0xff,
        sess->addr.src_port,
        dst_addr & 0xff, (dst_addr >> 8) & 0xff, (dst_addr >> 16) & 0xff, (dst_addr >> 24) & 0xff,
        sess->addr.dst_port);

    flags = 
#ifdef USE_AIO_
    O_APPEND |
#endif
    O_WRONLY | O_CREAT | O_TRUNC;

        // new filename directory structure thingy
    dir = directory_structure(temp);    
        if (dir == NULL)
    {
        log_z("couldn't calculate directory structure for: \'%s\'\n", filename);
        return -1;
    }
    if (_mkdir(dir))
    {
        log_z("couldn't create directory structure for: \'%s\'\n", dir);
        return -1;
    }
        snprintf(fullpath, sizeof(fullpath), "%s%s", dir, filename);
    if((sess->fd = open(fullpath, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
    {
        log_z("couldn't open file \'%s\': %s\n", fullpath, strerror(errno));
        return -1;
    }
    // write pcap file header
    write(sess->fd, (char *)&ctx->fh, sizeof(ctx->fh));

#ifdef USE_AIO_
    CLEAR(sess->aiocb);
    sess->aiocb.aio_fildes = sess->fd;
    sess->aiocb.aio_sigevent.sigev_notify = SIGEV_NONE;
#endif

    sess->npackets = 0;
    sess->nwritten = 0;
#ifdef DEBUG
    strncpy(sess->filename, fullpath, sizeof(sess->filename));
#endif
    return 0;
}

static int session_fclose(context_t *ctx, session_t *sess)
{
    if(sess->fd > 0)
    {
#ifdef USE_AIO_
        wait_pending_aio(&sess->aiocb);
        if(ctx->pending_aio == &sess->aiocb)
            ctx->pending_aio = NULL;
#endif
        close(sess->fd);
        sess->fd = -1;

        sess->npackets = 0;
        sess->nwritten = 0;
    }
//    log_dbg("%s %s\n", __FUNCTION__, sess->filename);

    return 0;
}

static int session_close(context_t *ctx, session_t *sess)
{
    if(sess)
    {
        session_fclose(ctx, sess);

        sess->state = TCP_STATE_CLOSED;
        sess->statex =     STATE_IDLE;

//        log_dbg("%s %s\n", __FUNCTION__, sess->filename);
    }
    return 0;
}

static int session_free(context_t *ctx, session_t *sess)
{
    if(sess)
    {
        session_close(ctx, sess);

        list_del(&sess->list);
        hash_remove(ctx->sess_hash, (const void *)&sess->addr);
        hash_remove(ctx->sess_hash, (const void *)&sess->addr2);
        free(sess);
    }
    return 0;
}

static int session_is_full(context_t *ctx, session_t *sess)
{
    return max_sess_length < sess->nwritten;
}

static int session_is_expired(context_t *ctx, session_t *sess, struct timeval *pnow)
{
    struct timeval tvdiff;
    timersub(pnow, &sess->access, &tvdiff);

    return tvdiff.tv_sec > idle_timeout;
}

static int session_write_packet_impl(context_t *ctx, session_t *sess, 
    const struct pcap_pkthdr *header, uint8_t *buf, int len)
{
#ifdef USE_AIO_

    sess->aiocb.aio_buf     = buf;
    sess->aiocb.aio_nbytes  = len;
    sess->aiocb.aio_fildes  = sess->fd;

    if(aio_write(&sess->aiocb) < 0)
        log_z("aio_write failed: %s\n", strerror(errno));

    ctx->pending_aio = &sess->aiocb;

#else
    write(sess->fd, buf, len);
#endif

    sess->nwritten+= header->caplen;
    sess->npackets++;
    ctx->npackets++;
    sess->access = header->ts;

    return 0;
}

static int session_write_packet(context_t *ctx, session_t *sess, const struct pcap_pkthdr *header, 
    struct addr_tuple *addr, uint8_t *buf, int len)
{
    if(session_is_full(ctx, sess))
    {
        log_dbg("flushing session, size limit reached. %"PRIu64" bytes written, %"PRIu64" packets\n", 
            sess->nwritten, sess->npackets);

        session_fclose(ctx, sess);
    }
    if(sess->fd < 0)
    {
        sess->start = header->ts;
        if(session_fopen(ctx, sess) < 0)
            return -1;
    }

    switch(sess->addr.proto)
    {
        case IPPROTO_TCP:
            return tcp_session_write_packet(ctx, sess, header, addr, buf, len);

        case IPPROTO_UDP:
            return udp_session_write_packet(ctx, sess, header, addr, buf, len);

        default:
            break;
    }

    return session_write_packet_impl(ctx, sess, header, buf, len);
}

static int udp_session_write_packet(context_t *ctx, session_t *sess, const struct pcap_pkthdr *header, 
    struct addr_tuple *addr, uint8_t *buf, int len)
{
    return session_write_packet_impl(ctx, sess, header, buf, len);
}

static int tcp_session_write_packet(context_t *ctx, session_t *sess, const struct pcap_pkthdr *header, 
    struct addr_tuple *addr, uint8_t *buf, int len)
{
    int from_src = 0;
    uint8_t *packet = buf + HEADER_LEN;

//    struct iphdr  *ip_hdr;
    struct tcphdr  *tcp_hdr;
    enum tcp_state last_state;

//    ip_hdr  = (struct iphdr *)(packet + sizeof(struct ethhdr));
    tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if(sess->addr.src_addr == addr->src_addr && sess->addr.src_port == addr->src_port)
        from_src = 1;

    if(1)
    {
        char tmp[128];
        tmp[0] = '\0';

        snprintf(tmp, sizeof(tmp), "%s:%d ", 
            inet_ntoa(*(struct in_addr *)&addr->dst_addr), addr->dst_port);
        if(tcp_hdr->fin) strcat(tmp, "F");
        if(tcp_hdr->syn) strcat(tmp, "S");
        if(tcp_hdr->ack) strcat(tmp, "A");
        if(tcp_hdr->rst) strcat(tmp, "R");
        if(tcp_hdr->psh) strcat(tmp, "P");

        log_dbg("%s:%d -> %s\n", 
            inet_ntoa(*(struct in_addr *)&addr->src_addr), addr->src_port,
            tmp);
    }

    if(tcp_hdr->rst)
    {
        log_dbg("%s->TCP_STATE_CLOSED (reset)\n", state_str(sess->state));
        sess->state = TCP_STATE_CLOSED;
        goto save__;
    }
    last_state = sess->state;

    /* TCP FSM */
    switch(sess->state)
    {
        case TCP_STATE_ESTABLISHED:
            if(tcp_hdr->fin)
                sess->state = (from_src ? TCP_STATE_FIN_WAIT_1 : TCP_STATE_CLOSE_WAIT);
            break;

        case TCP_STATE_FIN_WAIT_1:
            if(!from_src && tcp_hdr->fin)
                sess->state = (tcp_hdr->ack ? TCP_STATE_TIME_WAIT : TCP_STATE_CLOSING);
            else if(!from_src && tcp_hdr->ack)
                sess->state = TCP_STATE_FIN_WAIT_2;
            break;

        case TCP_STATE_FIN_WAIT_2:
            if(!from_src && tcp_hdr->fin)
                sess->state = TCP_STATE_TIME_WAIT;
            break;

        case TCP_STATE_CLOSING:
            if(!from_src && tcp_hdr->ack)
                sess->state = TCP_STATE_TIME_WAIT;
            break;

        case TCP_STATE_CLOSE_WAIT:
            if(from_src && tcp_hdr->fin)
                sess->state = TCP_STATE_LAST_ACK;
            break;

        case TCP_STATE_LAST_ACK:
            if(!from_src && tcp_hdr->ack)
                sess->state = TCP_STATE_CLOSED;
            break;

        case TCP_STATE_TIME_WAIT:
            if(from_src && tcp_hdr->ack)
                sess->state = TCP_STATE_CLOSED;
            break;

        default:
            break;
    }
    if(last_state != sess->state)
        log_dbg("%s->%s\n", state_str(last_state), state_str(sess->state));

save__:
    session_write_packet_impl(ctx, sess, header, buf, len);

    // suspend closed session
    if(sess->state == TCP_STATE_CLOSED)
        session_fclose(ctx, sess);

    return 0;
}

static int device_open(context_t *ctx, params_t *pp)
{
    if(pcap_lookupnet(pp->devname, &ctx->net, &ctx->mask, ctx->errbuf) < 0)
    {
        log_z("couldn't get netmask for device %s: %s\n", pp->devname, ctx->errbuf);
        ctx->net = 0;
        ctx->mask = 0;
    }
    ctx->handle = pcap_open_live(pp->devname, SNAP_LEN, 1, 1000, ctx->errbuf);
    if(!ctx->handle)
    {
        log_z("couldn't open device %s: %s\n", pp->devname, ctx->errbuf);
        return -1;
    }

    if(pcap_datalink(ctx->handle) != DLT_EN10MB)
    {
        log_z("%s is not an Ethernet device\n", pp->devname);

        return -1;
    }

    if(pp->expr)
    {
        if(pcap_compile(ctx->handle, &ctx->fp, pp->expr, 0, ctx->net) < 0)
        {
            log_z("couldn't compile filter %s: %s\n", 
                pp->expr, pcap_geterr(ctx->handle));
            return -1;
        }

        if(pcap_setfilter(ctx->handle, &ctx->fp) < 0)
        {
            log_z("couldn't install filter %s: %s\n", 
                pp->expr, pcap_geterr(ctx->handle));
            return -1;
        }
    }

    return 0;
}

static int device_close(context_t *ctx)
{
    if(ctx && ctx->handle)
    {
        pcap_freecode(&ctx->fp);
        pcap_close(ctx->handle);
        ctx->handle = NULL;
    }    

    return 0;
}

static int context_open(context_t *ctx, params_t *pp)
{
    ctx->rbuf = ring_buffer_alloc(pp->rbuf_capacity);
    if(!ctx->rbuf)
    {
        log_z("couldn't allocate capture buffer, requested %"PRIu64" bytes\n", pp->rbuf_capacity);
        return -1;
    }

    if(!(ctx->cache.buf = (uint8_t *)malloc(pp->cache_capacity)))
    {
        log_z("couldn't allocate capture cache, requested %u bytes\n", pp->cache_capacity);
        goto fail__;
    }
    ctx->cache.capacity = pp->cache_capacity;
    ctx->cache.size = 0;

    if(!(ctx->sessions = (session_t *)malloc(sizeof(session_t))))
    {
        log_z("couldn't allocate sessions list\n");
        goto fail__;
    }
    CLEAR(*ctx->sessions);
    INIT_LIST_HEAD(&ctx->sessions->list);

    // @TODO make hash settings configurable?
    ctx->sess_hash = hash_init(1 << 16, 123, addr_hash_function, addr_compare_function);
    if(!ctx->sess_hash)
        goto fail__;

    CLEAR(ctx->fh);

    {
        char tmpstr[] = "/tmp/pcap_hdr.XXXXXX";
        int tmpfd = mkstemp(tmpstr);
        if(tmpfd >= 0) 
        {
            pcap_dumper_t *dump = pcap_dump_fopen(main_ctx.handle, fdopen(tmpfd,"w"));
            if (dump) pcap_dump_close(dump);
            tmpfd = open(tmpstr, O_RDONLY);    /* get pcap to create a header */
            if (tmpfd >= 0) read(tmpfd, (char *)&ctx->fh, sizeof(ctx->fh));
            if (tmpfd >= 0) close(tmpfd);
            unlink(tmpstr);
            ctx->fh.snaplen = SNAP_LEN;
        }
    }
    log_z("pcap format, magic: %x, version: %u:%u, thiszone: %u, sigfigs: %u, linktype: %u\n",
        ctx->fh.magic, ctx->fh.version_major, ctx->fh.version_minor, 
        ctx->fh.thiszone, ctx->fh.sigfigs, ctx->fh.linktype);

    gettimeofday(&ctx->last_gc, NULL);
//    ctx->last_gc = time(NULL);
    return 0;

fail__:

    ring_buffer_free(ctx->rbuf);
    ctx->rbuf = NULL;

    free(ctx->sessions);
    free(ctx->cache.buf);
    ctx->cache.buf = NULL;
    ctx->cache.capacity = ctx->cache.size = 0;

    return -1;
}

static int context_close(context_t *ctx)
{
    struct hash_bucket *bucket;

    if(ctx && ctx->sess_hash)
    {
        // free all sessions
        while((bucket = hash_first(ctx->sess_hash)))
        {
            struct session *sess = (struct session *)bucket->value;
            session_free(ctx, sess);
        }

        hash_free(ctx->sess_hash);
        ctx->sess_hash = NULL;
    }
    if(ctx && ctx->rbuf)
    {
        ring_buffer_free(ctx->rbuf);
        ctx->rbuf = NULL;
    }
    if(ctx && ctx->cache.buf)
    {
        free(ctx->cache.buf);
        ctx->cache.buf = NULL;
        ctx->cache.capacity = ctx->cache.size = 0;
    }
    if(ctx && ctx->sessions)
    {
        free(ctx->sessions);
        ctx->sessions = NULL;
    }

    return 0;
}

static void signal_handler(int sig)
{
    switch(sig) 
    {
        case SIGTERM:
        case SIGINT:
            running = 0;

            break;
    }
}

static void usage(const char *progname)
{
    fprintf(stderr, "version: %d.%d.%d, usage: %s <options>\n"
        "options: \n"
        "-d <input device>\n"
        "[-o <output directory>]\n"
        "[-e <filter expression>]\n"
        "[-L <max session size, MB>]\n"
        "[-C <capture buffer capacity, MB>]\n"
        "[-c <cache buffer capacity, KB>]\n"
        "[-t <idle session timeout (in sec)>]\n"
        "[-h]\n", 
        version_major, version_minor, version_sub, progname);
}

int main(int argc, char **argv)
{
    int  option;
    struct params params;
    struct stat st;

    // cleanup and set default
    CLEAR(params);
    params.rbuf_capacity  = rbuf_capacity;
    params.cache_capacity = cache_capacity;

    while((option = getopt(argc, argv, "d:e:L:c:C:t:o:h")) > 0) 
    {
        switch(option) 
        {
            case 'd':
                params.devname = optarg;
                break;

            case 'e':
                params.expr = optarg;
                break;

            case 'o':
                params.output_dir = optarg;
                break;

            case 'L':
                max_sess_length = (uint64_t)atol(optarg) * 1024 * 1024;
                break;

            case 'C':
                params.rbuf_capacity = (uint64_t)atol(optarg) * 1024 * 1024;
                break;

            case 'c':
                params.cache_capacity = atol(optarg) * 1024;
                break;

            case 't':
                idle_timeout = atol(optarg);
                break;

            case 'h':
                usage(argv[0]);
                exit(1);

            default:
                fprintf(stderr, "unknown option %c\n", option);
                usage(argv[0]);
                exit(1);
        }
    }
    if(!params.devname)
    {
        log_z("device name must be specified\n");
        usage(argv[0]);
        exit(1);
    }
    if(params.cache_capacity > params.rbuf_capacity / 4)
    {
        log_z("cache capacity is too big: %u, buffer capacity: %"PRIu64"\n",
            params.cache_capacity, params.rbuf_capacity);

        exit(1);
    }

        if(stat(params.output_dir, &st) != 0)
    {
        log_z("output directory: %s, not present\n", params.output_dir);
        exit(1);
    }
        if (getuid() == 0 || geteuid() == 0)
        {
                if (chroot(params.output_dir) != 0 || chdir("/") != 0)
                {
                        log_z("chroot to output directory: %s, unsuccessful - %s\n", params.output_dir, pcap_strerror(errno));
                        exit(1);
                }
    }

    signal(SIGHUP,  SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    log_z("input device: %s, filter expression: \'%s\', max session size: %"PRIu64" bytes, buffer capacity: %"PRIu64" MB, cache capacity: %u KB, idle timeout: %u sec\noutput directory: %s\n",
        params.devname, (params.expr ? params.expr : ""), max_sess_length, 
        params.rbuf_capacity / (1024*1024), params.cache_capacity / (1024),
        idle_timeout, (params.output_dir ? params.output_dir : "<cwd>"));

    run(&params);

    return 0;
}


