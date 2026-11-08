/* Thin C layer between FeroTRX and DPDK.
 *
 * DPDK's fast path (rte_eth_tx_burst, mbuf allocation) is made of static
 * inline functions, so Rust cannot call it directly; these wrappers are
 * compiled against the installed DPDK headers by build.rs. Every function
 * returns 0 or a count on success and a negative errno on failure. */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_cycles.h>

/* Up to this many packets are passed to the NIC per call. */
#define FTRX_BURST 64

int ftrx_dpdk_init(int argc, char **argv) {
    int r = rte_eal_init(argc, argv);
    return r < 0 ? -rte_errno : 0;
}

const char *ftrx_dpdk_strerror(int err) { return rte_strerror(err); }

/* Registers the calling thread with EAL so it gets a mempool cache. */
void ftrx_dpdk_register_thread(void) {
    if (rte_lcore_id() == LCORE_ID_ANY)
        (void)rte_thread_register();
}

uint16_t ftrx_dpdk_port_count(void) { return rte_eth_dev_count_avail(); }

/* Finds the port called `name` (a PCI address, a vdev name like net_null0 or
 * a port number), probing it as a new device if it is not there yet. */
int ftrx_dpdk_find_port(const char *name, const char *devargs, uint16_t *port) {
    char *end = NULL;
    unsigned long n = strtoul(name, &end, 10);
    if (end != name && *end == '\0') {
        if (n >= RTE_MAX_ETHPORTS || !rte_eth_dev_is_valid_port((uint16_t)n))
            return -ENODEV;
        *port = (uint16_t)n;
        return 0;
    }
    if (rte_eth_dev_get_port_by_name(name, port) == 0)
        return 0;
    int r = rte_dev_probe(devargs);
    if (r < 0)
        return r;
    return rte_eth_dev_get_port_by_name(name, port) == 0 ? 0 : -ENODEV;
}

/* Configures `port` with `queue + 1` TX queues and one RX queue (some drivers
 * insist on one) and starts it. `*pool` is created on first use and kept, so
 * a port can be set up again later. */
int ftrx_dpdk_setup(uint16_t port, uint16_t queue, uint16_t nb_desc, struct rte_mempool **pool,
                    char *info, size_t info_len) {
    struct rte_eth_dev_info dev_info;
    int r = rte_eth_dev_info_get(port, &dev_info);
    if (r < 0)
        return r;
    if (queue >= dev_info.max_tx_queues)
        return -EINVAL;
    int socket = rte_eth_dev_socket_id(port);
    if (socket < 0)
        socket = (int)rte_socket_id();
    if (*pool == NULL) {
        char pool_name[RTE_MEMPOOL_NAMESIZE];
        snprintf(pool_name, sizeof pool_name, "ftrx_tx_%u", port);
        /* 4 KiB of data per mbuf, so packets up to 4096 bytes fit in one. */
        *pool = rte_pktmbuf_pool_create(pool_name, 8191, 256, 0,
                                        RTE_PKTMBUF_HEADROOM + 4096, socket);
        if (*pool == NULL)
            return -rte_errno;
    }
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof conf);
    r = rte_eth_dev_configure(port, 1, queue + 1, &conf);
    if (r < 0)
        return r;
    uint16_t nb_rx = 1024, nb_tx = nb_desc;
    r = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx);
    if (r < 0)
        return r;
    r = rte_eth_rx_queue_setup(port, 0, nb_rx, socket, NULL, *pool);
    if (r < 0)
        return r;
    for (uint16_t q = 0; q <= queue; q++) {
        r = rte_eth_tx_queue_setup(port, q, nb_tx, socket, NULL);
        if (r < 0)
            return r;
    }
    r = rte_eth_dev_start(port);
    if (r < 0)
        return r;

    /* Give the link a few seconds to come up, as NICs need after a start. */
    struct rte_eth_link link;
    memset(&link, 0, sizeof link);
    for (int i = 0; i < 50; i++) {
        if (rte_eth_link_get_nowait(port, &link) == 0 && link.link_status == RTE_ETH_LINK_UP)
            break;
        rte_delay_ms(100);
    }
    char link_text[RTE_ETH_LINK_MAX_STR_LEN];
    rte_eth_link_to_str(link_text, sizeof link_text, &link);
    snprintf(info, info_len, "%s, %s", dev_info.driver_name, link_text);
    return link.link_status == RTE_ETH_LINK_UP ? 1 : 0;
}

/* Copies `n` packets into mbufs and sends them on `port`/`queue`. Waits while
 * the NIC's ring is full, up to `spin_limit` tries without progress; returns
 * how many were sent. */
int ftrx_dpdk_send(uint16_t port, uint16_t queue, struct rte_mempool *pool,
                   const uint8_t *const *data, const uint16_t *lens, uint16_t n,
                   uint64_t spin_limit) {
    uint16_t sent = 0;
    while (sent < n) {
        struct rte_mbuf *bufs[FTRX_BURST];
        uint16_t count = n - sent < FTRX_BURST ? n - sent : FTRX_BURST;
        if (rte_pktmbuf_alloc_bulk(pool, bufs, count) != 0)
            return sent > 0 ? sent : -ENOBUFS;
        for (uint16_t i = 0; i < count; i++) {
            char *dst = rte_pktmbuf_append(bufs[i], lens[sent + i]);
            if (dst == NULL) {
                rte_pktmbuf_free_bulk(bufs, count);
                return -EMSGSIZE;
            }
            memcpy(dst, data[sent + i], lens[sent + i]);
        }
        uint16_t done = 0;
        uint64_t idle = 0;
        while (done < count) {
            uint16_t k = rte_eth_tx_burst(port, queue, bufs + done, count - done);
            done += k;
            if (k == 0 && ++idle > spin_limit)
                break;
            if (k > 0)
                idle = 0;
        }
        if (done < count) {
            rte_pktmbuf_free_bulk(bufs + done, count - done);
            return sent + done > 0 ? sent + done : -EAGAIN;
        }
        sent += count;
    }
    return sent;
}

void ftrx_dpdk_stop(uint16_t port, uint16_t queue) {
    /* Let the NIC finish what is queued before the port goes down. */
    rte_delay_ms(10);
    (void)rte_eth_tx_done_cleanup(port, queue, 0);
    (void)rte_eth_dev_stop(port);
}

/* The port's drop counters: imissed, ierrors, oerrors, rx_nombuf. */
int ftrx_dpdk_stats(uint16_t port, uint64_t *out) {
    struct rte_eth_stats st;
    int r = rte_eth_stats_get(port, &st);
    if (r < 0)
        return r;
    out[0] = st.imissed;
    out[1] = st.ierrors;
    out[2] = st.oerrors;
    out[3] = st.rx_nombuf;
    return 0;
}

int ftrx_dpdk_port_name(uint16_t port, char *name, size_t len) {
    char buf[RTE_ETH_NAME_MAX_LEN];
    int r = rte_eth_dev_get_name_by_port(port, buf);
    if (r < 0)
        return r;
    snprintf(name, len, "%s", buf);
    return 0;
}

/* Takes in every frame (promiscuous and all-multicast), for a port that
 * receives for emulated hosts with MAC addresses of their own. */
int ftrx_dpdk_promisc(uint16_t port) {
    int r = rte_eth_promiscuous_enable(port);
    if (r < 0 && r != -ENOTSUP)
        return r;
    r = rte_eth_allmulticast_enable(port);
    if (r < 0 && r != -ENOTSUP)
        return r;
    return 0;
}

/* Receives up to `max` (at most FTRX_BURST) frames from RX queue 0 of
 * `port` and copies them into `out`, one every `slot` bytes, their lengths
 * into `lens`. Frames longer than `slot` are dropped. Returns how many were
 * copied. */
int ftrx_dpdk_recv(uint16_t port, uint8_t *out, size_t slot, uint16_t *lens, uint16_t max) {
    struct rte_mbuf *bufs[FTRX_BURST];
    if (max > FTRX_BURST)
        max = FTRX_BURST;
    uint16_t got = rte_eth_rx_burst(port, 0, bufs, max);
    uint16_t n = 0;
    for (uint16_t i = 0; i < got; i++) {
        struct rte_mbuf *m = bufs[i];
        uint32_t len = rte_pktmbuf_pkt_len(m);
        if (len <= slot && len <= UINT16_MAX) {
            uint8_t *dst = out + (size_t)n * slot;
            for (struct rte_mbuf *s = m; s != NULL; s = s->next) {
                memcpy(dst, rte_pktmbuf_mtod(s, const uint8_t *), s->data_len);
                dst += s->data_len;
            }
            lens[n++] = (uint16_t)len;
        }
        rte_pktmbuf_free(m);
    }
    return n;
}
