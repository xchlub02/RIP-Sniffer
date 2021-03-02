/**
 * @author Pavel Chlubna, xchlub02
 * @date November, 2018
 */

#ifndef ISA_PACKET_STRUCTURE_H
#define ISA_PACKET_STRUCTURE_H

#include <stdint.h>
#include <netinet/ip.h>

#define HEADER_LEN 4
#define ENTRY_LEN 20


/*
 * Jak maji spravne vypadat struktury jsem nastudoval
 * zejmena v manualovych strankach prilozenych v zadani
 * a take v prednaskach ISA a IPK
 *
 * mimo jiné jsem pouzil k inspiraci take clanky:
 * http://docwiki.cisco.com/wiki/Routing_Information_Protocol#RIP_Packet_Format
 * https://barrgroup.com/Embedded-Systems/How-To/Internet-Protocol
 * http://www.ietf.org/rfc/rfc2460.txt
 * https://stackoverflow.com/questions/7980585/ipv6-raw-socket-programming-with-native-c
 * http://minirighi.sourceforge.net/html/structudp.html
 */


typedef struct rip_header
{
    uint8_t command;
    uint8_t version;
    uint16_t zero_fill;
}rip_header;


typedef struct rip_entry_table {
    uint16_t addr_faml;
    uint16_t route_tag;

    union data
    {
        struct
        {
            __u_char authentication[16];
        };
	    struct
        {
            uint16_t offset;
            uint8_t key_id;
            uint8_t auth_data_len;
            uint32_t seq_number;
        };

        struct
        {
            struct in_addr ip_addr;
            struct in_addr mask;
            struct in_addr next_hop;
            uint32_t metric;
        };
    }data;
}rip_entry_table;


typedef struct ripng_entry_table
{
    struct in6_addr prefix;
    uint16_t route_tag;
    uint8_t prefix_length;
    uint8_t metric;
} ripng_entry_table;


typedef struct ipv4_header
{
    uint8_t   ver_hlen;   /* Header version and length (dwords). */
    uint8_t   service;    /* Service type. */
    uint16_t  length;     /* Length of datagram (bytes). */
    uint16_t  ident;      /* Unique packet identification. */
    uint16_t  fragment;   /* Flags; Fragment offset. */
    uint8_t   timetolive; /* Packet time to live (in network). */
    uint8_t   protocol;   /* Upper level protocol (UDP, TCP). */
    uint16_t  checksum;   /* IP header checksum. */
    struct in_addr  src_addr;   /* Source IP address. */
    struct in_addr  dest_addr;  /* Destination IP address. */
} ipv4_header;


typedef struct ipv6_header
{
    uint32_t ip6_un1_flow; /* 4 bits version, 8 bits TC, 20 bits flow-ID */
    uint16_t ip6_un1_plen; /* payload length */
    uint8_t ip6_un1_nxt; /* next header */
    uint8_t ip6_un1_hlim; /* hop limit */
    struct in6_addr ip6_src; /* source address */
    struct in6_addr ip6_dst; /* destination address */
} ipv6_header;


typedef struct udp_header
{
    uint16_t udp_src; /* Source port */
    uint16_t udp_dest; /* Destination port */
    uint16_t udp_length; /* Total length */
    uint16_t udp_sum; /* Checksum */
} udp_header;

#endif //ISA_PACKET_STRUCTURE_H
