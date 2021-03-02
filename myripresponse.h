/**
 * @author Pavel Chlubna, xchlub02
 * @date November, 2018
 */

#ifndef ISA_MYRIPRESPONSE_H
#define ISA_MYRIPRESPONSE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>

typedef struct res_arg {
    char interface[256];
    struct in6_addr address, nexthop;
    bool nexth;
    uint8_t	prefix;
    uint8_t metric;
    uint16_t tag;
} res_arg;

/**
 * @brief create socket and sends packet to multicast
 * @param args structure filled with args from console
 */
void send_packet(res_arg *args);

/**
 * @brief allocate memory for packet and fills him with argumets
 * @param args structure filled with args from console
 * @param size size of created packet
 * @return pointer to packet
 */
u_char *set_packet(const res_arg *args, size_t *size);



#endif //ISA_MYRIPRESPONSE_H
